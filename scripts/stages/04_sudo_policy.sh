#!/usr/bin/env bash
set -euo pipefail

id -u trainee &>/dev/null || useradd -m trainee
cat >/etc/sudoers.d/90-training-stage04 <<'SUDO'
# INTENTIONAL: overly broad sudo command for training.
trainee ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart *
SUDO
chmod 0440 /etc/sudoers.d/90-training-stage04
visudo -cf /etc/sudoers >/dev/null
