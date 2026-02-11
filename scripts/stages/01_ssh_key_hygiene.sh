#!/usr/bin/env bash
set -euo pipefail

install -d -m 0700 /opt/training/stage01
cat >/opt/training/stage01/scenario.txt <<'TXT'
KONU: SSH anahtar hijyeni
ZAFIYET: /home/analyst/.ssh dizini world-readable bırakıldı.
GÖREV: SSH key material izinlerini 700/600 seviyesine çek.
TXT

id -u analyst &>/dev/null || useradd -m analyst
install -d -m 0755 -o analyst -g analyst /home/analyst/.ssh
touch /home/analyst/.ssh/authorized_keys
chown analyst:analyst /home/analyst/.ssh/authorized_keys
chmod 0644 /home/analyst/.ssh/authorized_keys
