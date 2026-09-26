"""Five bounded attack demonstrations against the disposable Invoice Lab."""
import argparse
import json
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
import requests
import psycopg
from psycopg import sql

OUT = Path('/evidence')
def secret(name):
    return Path('/run/secrets', name).read_text().strip()
def connect(user='app_runtime', password=None):
    return psycopg.connect(host='db', dbname='invoice_lab', user=user,
        password=password or secret('runtime_current' if user=='app_runtime' else 'lab_admin'),
        sslmode='verify-full', sslrootcert='/certs/ca.crt', connect_timeout=3)
def login(mode):
    base='http://'+mode+':8000'
    c=requests.Session()
    token=c.get(base+'/api/session',timeout=5).json()['csrf']
    r=c.post(base+'/api/login',json={'username':'alice','password':'Lab-A-2026!'},
             headers={'X-CSRF-Token':token},timeout=5)
    r.raise_for_status()
    return c,base
def expect(ok, label):
    if not ok: raise AssertionError(label)
def web_injection():
    results={}
    for mode in ('vulnerable','query-fixed','hardened'):
        c,base=login(mode)
        r=c.get(base+'/api/invoices',params={'q':"' OR '1'='1' -- "},timeout=5)
        ids=[x['id'] for x in r.json().get('invoices',[])]
        expect(r.status_code==200 and ids==(['INV-001','INV-002','INV-003'] if mode=='vulnerable' else []),mode+' injection')
        normal=c.get(base+'/api/invoices',timeout=5)
        expect([x['id'] for x in normal.json()['invoices']]==['INV-001','INV-003'],'normal own invoices')
        results[mode]={'invoice_ids':ids,'normal_own_invoices':2}
    return results
def web_idor():
    results={}
    for mode in ('vulnerable','query-fixed','hardened'):
        c,base=login(mode)
        r=c.get(base+'/api/invoices/INV-002',timeout=5)
        expect(r.status_code==(404 if mode=='hardened' else 200),mode+' IDOR')
        if mode!='hardened':expect(r.json()['invoice']['customer_id']=='B','foreign owner')
        own=c.get(base+'/api/invoices/INV-001',timeout=5)
        expect(own.status_code==200 and own.json()['invoice']['customer_id']=='A','own invoice')
        results[mode]={'foreign_invoice_http':r.status_code,'own_invoice_http':own.status_code}
    return results
def account_abuse():
    with connect('lab_admin') as c:
        before=c.execute("SELECT status FROM billing.invoices WHERE id='INV-002'").fetchone()[0]
        count=c.execute('SELECT count(*) FROM internal.audit_sentinel').fetchone()[0]
        expect(count==1,'baseline reads internal data')
        c.execute("UPDATE billing.invoices SET status='Demo-only' WHERE id='INV-002'")
        expect(c.execute("SELECT status FROM billing.invoices WHERE id='INV-002'").fetchone()[0]=='Demo-only','baseline modifies invoice')
        c.rollback()
    with connect('lab_admin') as c:
        expect(c.execute("SELECT status FROM billing.invoices WHERE id='INV-002'").fetchone()[0]==before,'rollback restores invoice')
    blocked={}
    for name,query in [('read_internal','SELECT * FROM internal.audit_sentinel'),
                       ('update_invoice',"UPDATE billing.invoices SET status='Demo-only' WHERE id='INV-002'")]:
        c=connect()
        try:
            c.execute(query)
            raise AssertionError('runtime unexpectedly allowed '+name)
        except psycopg.Error as exc:
            expect(exc.sqlstate=='42501','expected privilege rejection')
            blocked[name]=exc.sqlstate
        finally:
            c.rollback()
            c.close()
    with connect() as c:
        expect(c.execute('SELECT count(*) FROM billing.invoices').fetchone()[0]==3,'runtime positive SELECT')
    return {'baseline_internal_rows':count,'baseline_update':'succeeded then rolled back',
            'runtime_denials':blocked,'invoice_state_restored':True,'authorized_select_rows':3,
            'assumption':'direct database access with a supplied lab account; not web privilege escalation'}
def credential_reuse():
    admin=connect('lab_admin');admin.autocommit=True
    try:
        admin.execute(sql.SQL('ALTER ROLE app_runtime PASSWORD {}').format(sql.Literal(secret('runtime_old'))))
        with connect(password=secret('runtime_old')) as c:
            expect(c.execute('SELECT 1').fetchone()[0]==1,'old credential before rotation')
        admin.execute(sql.SQL('ALTER ROLE app_runtime PASSWORD {}').format(sql.Literal(secret('runtime_current'))))
        try:
            with connect(password=secret('runtime_old')):
                pass
            raise AssertionError('old password accepted after rotation')
        except psycopg.OperationalError as exc:
            expect('password authentication failed' in str(exc),'must fail due to authentication')
        with connect() as c:
            expect(c.execute('SELECT 1').fetchone()[0]==1,'current password')
    finally:
        admin.execute(sql.SQL('ALTER ROLE app_runtime PASSWORD {}').format(sql.Literal(secret('runtime_current'))))
        admin.close()
    c,base=login('hardened')
    expect(c.get(base+'/api/invoices',timeout=5).status_code==200,'application recovers')
    return {'before_rotation':'old password accepted','after_rotation':'old password rejected',
            'current_password':'accepted','application_http':200,
            'scope':'new connections only; existing sessions are not revoked by password rotation'}
def report(run_id):
    core=json.loads((OUT/'attacks-core.json').read_text())
    network=json.loads((OUT/'network.json').read_text())
    expect(core['run_id']==run_id and network.get('run_id')==run_id,'evidence must come from this run')
    records=core['scenarios']
    expect({s['id'] for s in records}=={'S1','S2','S3','S5'} and len(records)==4,'four core scenarios required')
    privilege=next(s for s in records if s['id']=='S3')
    records.append({'id':'S4','name':'Valid credential from forbidden source','passed':network['passed'],
                    'actual':{'source':'172.30.26.30','rejection':network['actual'],
                              'authorized_source':'172.30.26.40',
                              'authorized_select_rows':privilege['actual'].get('authorized_select_rows')}})
    records.sort(key=lambda x:x['id'])
    result={'timestamp':datetime.now(timezone.utc).isoformat(),'run_id':run_id,
            'passed':sum(x['passed'] for x in records),'total':5,'scenarios':records}
    (OUT/'attacks.json').write_text(json.dumps(result,indent=2))
    for s in records:print(('PASS ' if s['passed'] else 'FAIL ')+s['id']+' '+s['name'])
    print('FIVE SCENARIOS: '+str(result['passed'])+'/5')
    return result['passed']==5
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--run-id',default=str(uuid.uuid4()))
    p.add_argument('--scenario',choices=['S1','S2','S3','S5'])
    p.add_argument('--report',action='store_true')
    a=p.parse_args()
    if a.report:
        sys.exit(0 if report(a.run_id) else 1)
    jobs=[('S1','SQL injection',web_injection),('S2','IDOR',web_idor),
          ('S3','Excessive database account privileges',account_abuse),
          ('S5','Reuse of old database password',credential_reuse)]
    records=[]
    for ident,name,fn in jobs:
        if a.scenario and a.scenario!=ident:continue
        try:
            actual=fn();passed=True
        except Exception as exc:
            # Never serialize exception text that might include credentials.
            actual={'error_type':type(exc).__name__};passed=False
        records.append({'id':ident,'name':name,'passed':passed,'actual':actual})
        print(('PASS ' if passed else 'FAIL ')+ident+' '+name,flush=True)
        print(json.dumps(actual),flush=True)
    target='attack-'+a.scenario+'.json' if a.scenario else 'attacks-core.json'
    (OUT/target).write_text(json.dumps({'run_id':a.run_id,'timestamp':datetime.now(timezone.utc).isoformat(),'scenarios':records},indent=2))
    sys.exit(0 if records and all(x['passed'] for x in records) else 1)
