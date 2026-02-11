#!/usr/bin/env bash
set -euo pipefail

stage="${1:-}"
[[ -n "$stage" ]] || { echo "Kullanım: $0 <1-10>"; exit 1; }

case "$stage" in
  1) stat -c '%a' /home/analyst/.ssh ;;
  2) curl -sI http://127.0.0.1:8080/ | tr -d '\r' ;;
  3) getfacl /srv/labdata/customers.csv ;;
  4) sudo -l -U trainee ;;
  5) systemctl cat training-agent.service ;;
  6) cat /etc/audit/rules.d/training.rules ;;
  7) firewall-cmd --list-all --zone=internal-lab ;;
  8) cat /opt/training/stage08_container_run.sh ;;
  9) sed -n '1,80p' /etc/training-secrets/app.env ;;
  10) sed -n '1,120p' /etc/cron.d/ir-collector ;;
  *) echo "Geçersiz stage"; exit 1 ;;
esac
