#!/usr/bin/env bash
set -euo pipefail

install -d -m 0750 /etc/training-secrets
cat >/etc/training-secrets/app.env <<'ENV'
APP_NAME=training-api
# INTENTIONAL: hardcoded API token for rotation challenge.
API_TOKEN=token_stage9_rotate_me
ENV
chmod 0640 /etc/training-secrets/app.env
