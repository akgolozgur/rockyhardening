#!/usr/bin/env bash
set -euo pipefail

install -d -m 0750 /srv/labdata
cat >/srv/labdata/customers.csv <<'CSV'
id,email
1,user@example.local
CSV
chmod 0640 /srv/labdata/customers.csv

# INTENTIONAL: unnecessary ACL grants read access to others via group analytics
getent group analytics >/dev/null || groupadd analytics
setfacl -m g:analytics:r /srv/labdata/customers.csv
