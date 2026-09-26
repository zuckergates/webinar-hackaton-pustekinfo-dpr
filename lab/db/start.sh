#!/bin/bash
set -euo pipefail
install -d -m 700 -o postgres -g postgres /var/lib/postgresql/tls
install -m 600 -o postgres -g postgres /cert-source/server.key /var/lib/postgresql/tls/server.key
install -m 644 -o postgres -g postgres /cert-source/server.crt /var/lib/postgresql/tls/server.crt
exec /usr/local/bin/docker-entrypoint.sh "$@"
