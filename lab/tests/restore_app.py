import os
import sys
import json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
restored=json.loads(Path('/evidence/restore.json').read_text())
os.environ.update(LAB_MODE='hardened',DB_NAME=restored['database'],
                  DB_PASSWORD_FILE='/run/secrets/runtime_current',
                  SESSION_KEY_FILE='/run/secrets/session_hardened')
from app import app
records=[]
with app.test_client() as client:
    csrf=client.get('/api/session').json['csrf']
    r=client.post('/api/login',json={'username':'alice','password':'Lab-A-2026!'},headers={'X-CSRF-Token':csrf})
    records.append({'test':'restore application login','passed':r.status_code==200,'actual':r.status_code})
    r=client.get('/api/invoices')
    ids=[x['id'] for x in r.json.get('invoices',[])]
    records.append({'test':'restore application own list','passed':r.status_code==200 and ids==['INV-001','INV-003'],'actual':ids})
    r=client.get('/api/invoices/INV-002')
    records.append({'test':'restore application authorization','passed':r.status_code==404,'actual':r.status_code})
    r=client.get('/api/invoices',query_string={'q':"O'Reilly"})
    ids=[x['id'] for x in r.json.get('invoices',[])]
    records.append({'test':'restore application apostrophe','passed':ids==['INV-003'],'actual':ids})
report={'database':restored['database'],'passed':all(x['passed'] for x in records),'tests':records}
Path('/evidence/restore-app.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
sys.exit(0 if report['passed'] else 1)
