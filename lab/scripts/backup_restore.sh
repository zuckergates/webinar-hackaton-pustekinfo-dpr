#!/bin/bash
set -euo pipefail
umask 077
stamp=$(date -u +%Y%m%d_%H%M%S)
restore_db="invoice_restore_${stamp}"
dump="/evidence/invoice_${stamp}.dump"
started=$(date +%s)
pg_dump -U postgres -d invoice_lab -Fc -f "$dump"
createdb -U postgres "$restore_db"
pg_restore -U postgres -d "$restore_db" --exit-on-error "$dump"
psql -U postgres -d "$restore_db" -v ON_ERROR_STOP=1 -c "REVOKE ALL ON DATABASE $restore_db FROM PUBLIC; GRANT CONNECT ON DATABASE $restore_db TO app_runtime;" >/dev/null
query="SELECT md5(string_agg(row_to_json(i)::text, '' ORDER BY id)) FROM billing.invoices i"
original=$(psql -U postgres -d invoice_lab -Atc "$query")
restored=$(psql -U postgres -d "$restore_db" -Atc "$query")
rows=$(psql -U postgres -d "$restore_db" -Atc 'SELECT count(*) FROM billing.invoices')
test "$original" = "$restored"
test "$rows" = '3'
elapsed=$(( $(date +%s) - started ))
printf '{"passed":true,"database":"%s","rows":%s,"checksum":"%s","elapsed_seconds":%s,"dump":"%s"}\n' "$restore_db" "$rows" "$restored" "$elapsed" "$dump" > /evidence/restore.json
cat /evidence/restore.json
