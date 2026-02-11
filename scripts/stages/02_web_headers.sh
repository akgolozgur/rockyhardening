#!/usr/bin/env bash
set -euo pipefail

dnf -y install nginx >/dev/null
systemctl enable --now nginx

cat >/etc/nginx/conf.d/training.conf <<'NGINX'
server {
    listen 8080;
    server_name _;

    location / {
        add_header X-Frame-Options "SAMEORIGIN";
        # INTENTIONAL: CSP başlığı bilerek eksik bırakıldı.
        return 200 "stage02 web service";
    }
}
NGINX

nginx -t >/dev/null
systemctl reload nginx
