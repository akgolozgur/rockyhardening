#!/usr/bin/env bash
set -euo pipefail

install -d -m 0750 /var/log/ir
cat >/usr/local/bin/collect-ir.sh <<'IR'
#!/usr/bin/env bash
set -euo pipefail

tar -czf /var/log/ir/ir-$(date +%F).tgz /var/log/messages /var/log/secure
IR
chmod 0750 /usr/local/bin/collect-ir.sh

cat >/etc/cron.d/ir-collector <<'CRON'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
# INTENTIONAL: günlük toplama var ama integrity hash/immudability kontrolü yok.
30 2 * * * root /usr/local/bin/collect-ir.sh
CRON
