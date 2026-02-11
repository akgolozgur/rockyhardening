#!/usr/bin/env bash
set -euo pipefail

# 443 üzerinde çalışan, üretim-benzeri NGINX web servisi kurar.
# Önemli: "bilinen hiçbir açık yok" garantisi verilemez; bu script saldırı yüzeyini
# azaltır ve opsiyonel tek bir eğitim zafiyeti bırakmanıza izin verir.

log() {
  printf '[%s] %s\n' "$(date +'%F %T')" "$*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Bu script root ile çalışmalıdır." >&2
    exit 1
  fi
}

TSVC_NAME="${TSVC_NAME:-training-web}"
WEBROOT="${WEBROOT:-/var/www/training-web}"
CERT_PATH="${CERT_PATH:-/etc/pki/tls/certs/training-web.crt}"
KEY_PATH="${KEY_PATH:-/etc/pki/tls/private/training-web.key}"
INTENTIONAL_VULN="${INTENTIONAL_VULN:-false}"

usage() {
  cat <<'USAGE'
Kullanım:
  bash scripts/setup_professional_web443.sh

Opsiyonel env:
  TSVC_NAME=<nginx server_name>
  WEBROOT=<web root>
  CERT_PATH=<tls cert path>
  KEY_PATH=<tls key path>
  INTENTIONAL_VULN=<true|false>

Not:
  INTENTIONAL_VULN=true ise sadece eğitim için kontrollü bir debug endpoint'i açılır.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_root

log "NGINX ve OpenSSL kuruluyor"
dnf -y install nginx openssl >/dev/null

log "Web içeriği hazırlanıyor"
install -d -m 0755 "${WEBROOT}"
cat >"${WEBROOT}/index.html" <<'HTML'
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Training Web Service</title>
  <style>
    body { font-family: Inter, Arial, sans-serif; margin: 3rem; color: #1f2937; }
    .card { border: 1px solid #e5e7eb; border-radius: 14px; padding: 1.5rem; max-width: 760px; }
    h1 { margin-top: 0; }
    code { background: #f3f4f6; padding: .2rem .4rem; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Training Web Service</h1>
    <p>Service is online on <code>443/tcp</code>.</p>
    <p>Status endpoint: <code>/healthz</code></p>
  </div>
</body>
</html>
HTML

if [[ ! -f "${CERT_PATH}" || ! -f "${KEY_PATH}" ]]; then
  log "TLS sertifikası bulunamadı, self-signed sertifika üretiliyor"
  install -d -m 0755 "$(dirname "${CERT_PATH}")"
  install -d -m 0700 "$(dirname "${KEY_PATH}")"
  openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
    -subj "/C=TR/O=TrainingLab/CN=${TSVC_NAME}" \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" >/dev/null 2>&1
  chmod 0600 "${KEY_PATH}"
fi

log "Hardened NGINX konfigürasyonu yazılıyor"
cat >/etc/nginx/conf.d/training-web-443.conf <<NGINX
server {
    listen 443 ssl http2;
    server_name ${TSVC_NAME};

    root ${WEBROOT};
    index index.html;

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:20m;
    ssl_session_tickets off;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;

    location = /healthz {
        add_header Content-Type text/plain;
        return 200 'ok';
    }

    location / {
        try_files \$uri \$uri/ =404;
        limit_except GET HEAD { deny all; }
    }
NGINX

if [[ "${INTENTIONAL_VULN}" == "true" ]]; then
  log "INTENTIONAL_VULN=true: kontrollü debug endpoint açılıyor"
  install -d -m 0755 "${WEBROOT}/debug"
  echo "training debug info" > "${WEBROOT}/debug/info.txt"
  cat >>/etc/nginx/conf.d/training-web-443.conf <<'VULN'
    location /debug/ {
        autoindex on; # INTENTIONAL: debug dizin listesi açık
    }
VULN
fi

echo "}" >> /etc/nginx/conf.d/training-web-443.conf

log "NGINX test ve restart"
nginx -t >/dev/null
systemctl enable --now nginx >/dev/null
systemctl reload nginx >/dev/null

log "firewalld üzerinde https açılıyor"
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-service=https >/dev/null
  firewall-cmd --reload >/dev/null
fi

log "Tamamlandı"
