#!/usr/bin/env bash
set -euo pipefail

cat >/etc/systemd/system/training-agent.service <<'UNIT'
[Unit]
Description=Training Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/bash -c 'while true; do echo heartbeat; sleep 30; done'
User=nobody
Group=nobody
# INTENTIONAL: sandbox direktifleri eksik (NoNewPrivileges, ProtectSystem vs.)

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now training-agent.service
