"""Intentionally vulnerable educational checkpoints. Local isolated lab only."""
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone
import json
import os
import secrets
import hmac
import uuid
import logging
from flask import Flask, request, jsonify, session, g, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg
from psycopg.rows import dict_row

MODE = os.environ.get('LAB_MODE', 'hardened')
if MODE not in ('vulnerable', 'query-fixed', 'hardened'):
    raise RuntimeError('Unknown checkpoint')
HARD = MODE == 'hardened'
app = Flask(__name__)
# Werkzeug's default access log includes the raw URL. Use only our structured log.
logging.getLogger('werkzeug').setLevel(logging.ERROR)
app.config.update(SECRET_KEY=Path(os.environ.get('SESSION_KEY_FILE', '/run/secrets/session')).read_text().strip(),
                  SESSION_COOKIE_NAME='invoice_' + MODE.replace('-', '_'),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  SESSION_COOKIE_SECURE=False, MAX_CONTENT_LENGTH=8192)
# Known synthetic demo identities. No registration or production authentication intended.
USERS = {'alice': ('A', generate_password_hash('Lab-A-2026!')),
         'bob': ('B', generate_password_hash('Lab-B-2026!'))}

def connect():
    return psycopg.connect(host='db', dbname=os.environ.get('DB_NAME', 'invoice_lab'),
        user='app_runtime' if HARD else 'lab_admin',
        password=Path(os.environ['DB_PASSWORD_FILE']).read_text().strip(),
        sslmode='verify-full' if HARD else 'disable', sslrootcert='/certs/ca.crt',
        connect_timeout=3, row_factory=dict_row,
        options='-c statement_timeout=3000 -c default_transaction_read_only=on')

def audit(event, **fields):
    record = dict(time=datetime.now(timezone.utc).isoformat(), mode=MODE,
                  request_id=getattr(g, 'request_id', 'none'), event=event,
                  customer=session.get('customer'), **fields)
    line = json.dumps(record, separators=(',', ':'))
    print(line, flush=True)
    with open(f'/evidence/{MODE}.jsonl', 'a', encoding='utf-8') as f:
        f.write(line + '\n')

@app.before_request
def before():
    g.request_id = str(uuid.uuid4())
    if request.method == 'POST':
        expected = session.get('csrf', '')
        supplied = request.headers.get('X-CSRF-Token', '')
        if not expected or not hmac.compare_digest(expected, supplied):
            return jsonify(error='CSRF token tidak valid', request_id=g.request_id), 403

@app.after_request
def after(resp):
    resp.headers['X-Request-ID'] = g.request_id
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    return resp

def authenticated(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if 'customer' not in session:
            return jsonify(error='Silakan login', request_id=g.request_id), 401
        return fn(*args, **kwargs)
    return wrapped

@app.get('/')
def index():
    return render_template('index.html', mode=MODE)

@app.get('/api/session')
def state():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return jsonify(mode=MODE, customer=session.get('customer'), csrf=session['csrf'])

@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify(error='Input tidak valid'), 400
    username, password = data.get('username', ''), data.get('password', '')
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error='Input tidak valid'), 400
    user = USERS.get(username)
    if not user or not check_password_hash(user[1], password):
        audit('login_denied')
        return jsonify(error='Kredensial tidak valid'), 401
    session.clear()
    session.update(customer=user[0], csrf=secrets.token_urlsafe(32))
    audit('login_success')
    return jsonify(customer=user[0], csrf=session['csrf'])

@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get('/api/invoices')
@authenticated
def search():
    q = request.args.get('q', '')
    if len(q) > 200:
        return jsonify(error='Pencarian terlalu panjang'), 400
    customer = session['customer']
    columns = 'id, customer_id, description, amount, status'
    with connect() as conn:
        if MODE == 'vulnerable':
            # INTENTIONAL SQL injection for the read-only isolated lab.
            query = f"SELECT {columns} FROM billing.invoices WHERE customer_id = '{customer}' AND description ILIKE '%{q}%' ORDER BY id"
            rows = conn.execute(query).fetchall()
        else:
            query = f'SELECT {columns} FROM billing.invoices WHERE customer_id = %s AND description ILIKE %s ORDER BY id'
            rows = conn.execute(query, (customer, '%' + q + '%')).fetchall()
    audit('invoice_search', row_count=len(rows))
    return jsonify(invoices=rows, request_id=g.request_id)

@app.get('/api/invoices/<invoice_id>')
@authenticated
def detail(invoice_id):
    with connect() as conn:
        if HARD:
            row = conn.execute('SELECT * FROM billing.invoices WHERE id = %s AND customer_id = %s',
                               (invoice_id, session['customer'])).fetchone()
        else:
            # Parameterized already, but intentionally lacks object authorization.
            row = conn.execute('SELECT * FROM billing.invoices WHERE id = %s', (invoice_id,)).fetchone()
    if not row:
        audit('invoice_access_denied')
        return jsonify(error='Invoice tidak ditemukan atau akses ditolak', request_id=g.request_id), 404
    audit('invoice_read', invoice_id=row['id'])
    return jsonify(invoice=row, request_id=g.request_id)

@app.get('/api/demo-error')
@authenticated
def demo_error():
    # Deterministic training-only error to compare public response and sanitized log.
    with connect() as conn:
        conn.execute('SELECT 1 / 0')
    return jsonify(ok=True)

@app.get('/api/connection')
@authenticated
def connection():
    with connect() as conn:
        info = conn.execute('SELECT current_user AS role, ssl, version AS tls_version FROM pg_stat_ssl WHERE pid = pg_backend_pid()').fetchone()
    return jsonify(info=info, mode=MODE)

@app.errorhandler(psycopg.Error)
def database_error(exc):
    audit('database_error', sqlstate=exc.sqlstate)
    message = 'Terjadi kesalahan internal' if HARD else str(exc)
    return jsonify(error=message, request_id=g.request_id), 500

if __name__ == '__main__':
    # Exposed only to the internal Docker network and host loopback mappings.
    app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=False)
