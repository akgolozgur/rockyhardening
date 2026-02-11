#!/usr/bin/env bash
set -euo pipefail

systemctl enable --now auditd rsyslog

cat >/etc/audit/rules.d/training.rules <<'RULES'
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
# INTENTIONAL: /etc/shadow izleme kuralı eksik.
RULES

augenrules --load >/dev/null || true
