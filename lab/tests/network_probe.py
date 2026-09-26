import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
import psycopg
result=dict(test='valid credential from untrusted source 172.30.26.30',passed=False,
            run_id=os.environ.get('ATTACK_RUN_ID'),
            timestamp=datetime.now(timezone.utc).isoformat())
try:
    with psycopg.connect(host='db',dbname='invoice_lab',user='app_runtime',
                        password=Path('/run/secrets/runtime_current').read_text().strip(),
                        sslmode='verify-full',sslrootcert='/certs/ca.crt',connect_timeout=3):
        result['actual']='unexpected connection success'
except psycopg.OperationalError as exc:
    result['actual']=str(exc).strip()
    result['passed']='pg_hba.conf rejects connection' in str(exc) and '172.30.26.30' in str(exc)
Path('/evidence/network.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
sys.exit(0 if result['passed'] else 1)
