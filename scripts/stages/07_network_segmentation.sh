#!/usr/bin/env bash
set -euo pipefail

firewall-cmd --permanent --new-zone=internal-lab >/dev/null || true
firewall-cmd --permanent --zone=internal-lab --add-source=10.77.0.0/24 >/dev/null
firewall-cmd --permanent --zone=internal-lab --add-port=9000/tcp >/dev/null
# INTENTIONAL: east-west erişim için fazla geniş source CIDR bilerek bırakıldı.
firewall-cmd --reload >/dev/null
