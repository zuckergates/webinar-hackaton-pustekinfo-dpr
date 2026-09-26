"""Generate local disposable credentials and certificates. Never print secrets."""
from pathlib import Path
import os
import secrets
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.umask(0o077)
root = Path('/runtime')
if (root / 'READY').exists():
    print('Runtime already initialized. Existing credentials preserved.')
    raise SystemExit(0)
for d in ('secrets', 'db', 'public', 'init', 'private'):
    (root / d).mkdir(parents=True, exist_ok=True)
passwords = {}
for name in ('bootstrap', 'lab_admin', 'runtime_current', 'runtime_old',
             'session_vulnerable', 'session_query-fixed', 'session_hardened'):
    passwords[name] = secrets.token_urlsafe(36)
    (root / 'secrets' / name).write_text(passwords[name])

now = datetime.now(timezone.utc)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Invoice Lab Local CA')])
ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
      .public_key(key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .sign(key, hashes.SHA256()))
serverkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server = (x509.CertificateBuilder()
          .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'db')]))
          .issuer_name(ca.subject).public_key(serverkey.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('db')]), critical=False)
          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
          .sign(key, hashes.SHA256()))
def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
(root / 'private' / 'ca.key').write_bytes(pem_key(key))
(root / 'db' / 'server.key').write_bytes(pem_key(serverkey))
(root / 'db' / 'server.crt').write_bytes(server.public_bytes(serialization.Encoding.PEM))
(root / 'public' / 'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
# A different trust root is used to distinguish CA rejection from hostname rejection.
otherkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
other = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(otherkey.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .sign(otherkey, hashes.SHA256()))
(root / 'public' / 'untrusted-ca.crt').write_bytes(other.public_bytes(serialization.Encoding.PEM))

seed = f"""
CREATE ROLE lab_admin LOGIN SUPERUSER PASSWORD '{passwords['lab_admin']}';
CREATE ROLE lab_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  PASSWORD '{passwords['runtime_current']}';
REVOKE ALL ON DATABASE invoice_lab FROM PUBLIC;
GRANT CONNECT ON DATABASE invoice_lab TO app_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA billing AUTHORIZATION lab_owner;
CREATE SCHEMA internal AUTHORIZATION lab_owner;
SET ROLE lab_owner;
CREATE TABLE billing.invoices (
 id text PRIMARY KEY, customer_id text NOT NULL, description text NOT NULL,
 amount numeric(12,2) NOT NULL CHECK (amount >= 0), status text NOT NULL
);
INSERT INTO billing.invoices VALUES
 ('INV-001','A','Web hosting',1250000.00,'Paid'),
 ('INV-002','B','Database support',980000.00,'Pending'),
 ('INV-003','A','O''Reilly training',750000.00,'Paid');
CREATE TABLE internal.audit_sentinel (note text NOT NULL);
INSERT INTO internal.audit_sentinel VALUES ('Synthetic internal audit record');
RESET ROLE;
GRANT USAGE ON SCHEMA billing TO app_runtime;
GRANT SELECT ON billing.invoices TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lab_owner IN SCHEMA billing REVOKE ALL ON TABLES FROM PUBLIC;
"""
(root / 'init' / '01-seed.sql').write_text(seed)
(root / 'READY').write_text(now.isoformat())
print('Generated local credentials, CA, server certificate, and synthetic seed data.')
