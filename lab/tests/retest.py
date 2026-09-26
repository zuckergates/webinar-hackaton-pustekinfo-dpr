"""Executable evidence: fail nonzero on any incorrect expected behavior."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json
import time
from datetime import datetime, timezone
import requests
import psycopg
from psycopg import sql

OUT = Path('/evidence')
records = []
def check(name, condition, actual):
    item = dict(test=name, passed=bool(condition), actual=actual)
    records.append(item)
    print(('PASS ' if condition else 'FAIL ') + name, flush=True)
def password(name):
    return Path('/run/secrets/' + name).read_text().strip()
def db(user='app_runtime', **overrides):
    args = dict(host='db', dbname='invoice_lab', user=user,
                password=password('runtime_current' if user == 'app_runtime' else 'lab_admin'),
                sslmode='verify-full', sslrootcert='/certs/ca.crt', connect_timeout=3)
    args.update(overrides)
    return psycopg.connect(**args)
def denied(name, operation, expected):
    try:
        with db() as conn:
            conn.execute(operation)
        check(name, False, 'operation unexpectedly succeeded')
    except psycopg.Error as exc:
        check(name, exc.sqlstate == expected, {'sqlstate': exc.sqlstate})
def connection_denied(name, pattern, **params):
    try:
        with db(**params):
            pass
        check(name, False, 'connection unexpectedly succeeded')
    except psycopg.Error as exc:
        # Password values are never included in libpq diagnostic output here.
        patterns = (pattern,) if isinstance(pattern, str) else pattern
        check(name, any(p.lower() in str(exc).lower() for p in patterns), str(exc).strip())
def login(base, username='alice', secret='Lab-A-2026!'):
    client=requests.Session()
    token=client.get(base+'/api/session', timeout=5).json()['csrf']
    r=client.post(base+'/api/login', json=dict(username=username,password=secret),
                  headers={'X-CSRF-Token':token}, timeout=5)
    if r.status_code != 200:
        raise RuntimeError('Login failed: ' + str(r.status_code))
    return client, r.json()['csrf']

try:
    with db('lab_admin') as conn:
        version=conn.execute('SHOW server_version').fetchone()[0]
    payload="' OR '1'='1' -- "
    for mode in ('vulnerable','query-fixed','hardened'):
        base='http://'+mode+':8000'
        r=requests.get(base+'/api/invoices', timeout=5)
        check(mode+': unauthenticated access',r.status_code==401,r.status_code)
        c, csrf=login(base)
        r=c.get(base+'/api/invoices', timeout=5)
        ids=[x['id'] for x in r.json().get('invoices',[])]
        check(mode+': normal own invoices',r.status_code==200 and ids==['INV-001','INV-003'],ids)
        r=c.get(base+'/api/invoices',params={'q':payload}, timeout=5)
        ids=[x['id'] for x in r.json().get('invoices',[])]
        expected=['INV-001','INV-002','INV-003'] if mode=='vulnerable' else []
        check(mode+': SQL injection',r.status_code==200 and ids==expected,{'status':r.status_code,'invoice_ids':ids})
        r=c.get(base+'/api/invoices/INV-002', timeout=5)
        check(mode+': cross-customer object access',r.status_code==(404 if mode=='hardened' else 200),r.status_code)
        r=c.get(base+'/api/invoices/INV-001', timeout=5)
        check(mode+': own object access',r.status_code==200 and r.json()['invoice']['customer_id']=='A',r.status_code)
        r=c.get(base+'/api/invoices',params={'q':"O'Reilly"}, timeout=5)
        if mode=='vulnerable':
            check(mode+': apostrophe exposes bug',r.status_code==500,r.status_code)
        else:
            ids=[x['id'] for x in r.json().get('invoices',[])]
            check(mode+': apostrophe works',r.status_code==200 and ids==['INV-003'],ids)
        r=c.get(base+'/api/connection', timeout=5)
        info=r.json()['info']
        check(mode+': runtime role and TLS',info['role']==('app_runtime' if mode=='hardened' else 'lab_admin') and info['ssl']==(mode=='hardened'),info)
        r=c.get(base+'/api/demo-error', timeout=5)
        body=r.json()
        check(mode+': deterministic error',r.status_code==500,r.status_code)
        if mode=='hardened':
            check('hardened: public error sanitization',body['error']=='Terjadi kesalahan internal' and 'division' not in r.text,body)
            request_id=body['request_id']
            lines=[json.loads(line) for line in (OUT/'hardened.jsonl').read_text().splitlines() if line]
            matched=[x for x in lines if x['request_id']==request_id]
            check('hardened: log correlation',any(x['event']=='database_error' and x['sqlstate']=='22012' for x in matched),matched)
            logs=(OUT/'hardened.jsonl').read_text()
            check('hardened: logs exclude secrets and raw payload',all(s not in logs for s in [payload,'Lab-A-2026!',password('runtime_current')]),'checked secret and payload absence')
            check('hardened: cookie flags',bool(c.cookies) and all(x.has_nonstandard_attr('HttpOnly') and x.get_nonstandard_attr('SameSite')=='Strict' for x in c.cookies),'HttpOnly and SameSite=Strict')
            r=c.post(base+'/api/logout',json={}, timeout=5)
            check('hardened: CSRF enforced',r.status_code==403,r.status_code)
        b,_=login(base,'bob','Lab-B-2026!')
        r=b.get(base+'/api/invoices/INV-002', timeout=5)
        check(mode+': customer B own invoice',r.status_code==200 and r.json()['invoice']['customer_id']=='B',r.status_code)
        r=b.get(base+'/api/invoices/INV-001', timeout=5)
        check(mode+': reverse object access',r.status_code==(404 if mode=='hardened' else 200),r.status_code)

    with db() as conn:
        count=conn.execute('SELECT count(*) FROM billing.invoices').fetchone()[0]
        check('runtime: SELECT allowed',count==3,count)
        role=conn.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
        check('runtime: no administrative flags',not any(role),list(role))
        memberships=conn.execute('SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)').fetchone()[0]
        check('runtime: no inherited role memberships',memberships==0,memberships)
        owner=conn.execute("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='billing.invoices'::regclass").fetchone()[0]
        check('runtime: not table owner',owner=='lab_owner',owner)
    denied('runtime: UPDATE denied',"UPDATE billing.invoices SET status='Paid' WHERE false",'42501')
    denied('runtime: DELETE denied','DELETE FROM billing.invoices WHERE false','42501')
    denied('runtime: CREATE denied','CREATE TABLE billing.should_not_exist (id int)','42501')
    denied('runtime: internal schema denied','SELECT * FROM internal.audit_sentinel','42501')
    with db('lab_admin') as conn:
        count=conn.execute('SELECT count(*) FROM internal.audit_sentinel').fetchone()[0]
        check('baseline admin: internal schema reachable',count==1,count)
    connection_denied('TLS: plaintext connection denied','pg_hba.conf rejects connection',sslmode='disable')
    connection_denied('TLS: wrong hostname denied','does not match host name',host='wrong.local',hostaddr='172.30.26.10')
    # OpenSSL can report invalid padding when two distinct CA keys share a subject.
    # Both exact errors indicate certificate verification failed; generic connection failures do not pass.
    connection_denied('TLS: wrong CA denied',('certificate verify failed','SSL error: invalid padding'),sslrootcert='/certs/untrusted-ca.crt')
    # Actually rotate the runtime role, restoring the current secret in a finally block.
    admin=db('lab_admin');admin.autocommit=True
    try:
        admin.execute(sql.SQL('ALTER ROLE app_runtime PASSWORD {}').format(sql.Literal(password('runtime_old'))))
        with db(password=password('runtime_old')) as conn:
            check('rotation: old credential works before change',conn.execute('SELECT 1').fetchone()[0]==1,'connected')
        admin.execute(sql.SQL('ALTER ROLE app_runtime PASSWORD {}').format(sql.Literal(password('runtime_current'))))
        connection_denied('rotation: old credential rejected after change','password authentication failed',password=password('runtime_old'))
        with db() as conn:
            check('rotation: current credential works',conn.execute('SELECT 1').fetchone()[0]==1,'connected')
    finally:
        admin.execute(sql.SQL('ALTER ROLE app_runtime PASSWORD {}').format(sql.Literal(password('runtime_current'))))
        admin.close()
    c,_=login('http://hardened:8000')
    r=c.get('http://hardened:8000/api/invoices',timeout=5)
    check('rotation: application reconnects',r.status_code==200,r.status_code)
except Exception as exc:
    check('test runner completed',False,repr(exc))
finally:
    report=dict(timestamp=datetime.now(timezone.utc).isoformat(),postgres_version=locals().get('version'),
                passed=sum(x['passed'] for x in records),total=len(records),tests=records)
    (OUT/'retest.json').write_text(json.dumps(report,indent=2))
    print(f"RESULT {report['passed']}/{report['total']}")
    sys.exit(0 if records and all(x['passed'] for x in records) else 1)
