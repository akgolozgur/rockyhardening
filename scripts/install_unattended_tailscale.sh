#!/usr/bin/env bash
set -euo pipefail

# Rocky Linux 9.x için unattended tailscale kurulum helper'ı.
# Güvenlik notu: auth key'i script içine hardcode ETMEYİN.
# TS_AUTHKEY environment variable üzerinden verin.

log() {
  printf '[%s] %s\n' "$(date +'%F %T')" "$*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Bu script root ile çalışmalıdır." >&2
    exit 1
  fi
}

TS_AUTHKEY="${TS_AUTHKEY:-}"
TS_HOSTNAME="${TS_HOSTNAME:-$(hostname -s)}"
TS_ADVERTISE_TAGS="${TS_ADVERTISE_TAGS:-tag:training-admin}"
TS_ACCEPT_ROUTES="${TS_ACCEPT_ROUTES:-false}"
TS_SSH="${TS_SSH:-true}"

usage() {
  cat <<'USAGE'
Kullanım:
  TS_AUTHKEY=<tailscale_auth_key> bash scripts/install_unattended_tailscale.sh

Opsiyonel env değişkenleri:
  TS_HOSTNAME=<hostname>
  TS_ADVERTISE_TAGS=<tag:training-admin,tag:linux>
  TS_ACCEPT_ROUTES=<true|false>
  TS_SSH=<true|false>

Not:
  Auth key'i dosyaya yazmayın ve git'e commit etmeyin.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth-key)
      TS_AUTHKEY="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Bilinmeyen argüman: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_root

if [[ -z "${TS_AUTHKEY}" ]]; then
  echo "TS_AUTHKEY veya --auth-key zorunlu." >&2
  usage
  exit 1
fi

log "Tailscale repository ekleniyor"
dnf config-manager --add-repo https://pkgs.tailscale.com/stable/rhel/9/tailscale.repo >/dev/null

log "Tailscale kuruluyor"
dnf -y install tailscale >/dev/null

log "tailscaled servisi etkinleştiriliyor"
systemctl enable --now tailscaled >/dev/null

UP_FLAGS=(
  "--auth-key=${TS_AUTHKEY}"
  "--hostname=${TS_HOSTNAME}"
  "--advertise-tags=${TS_ADVERTISE_TAGS}"
  "--accept-routes=${TS_ACCEPT_ROUTES}"
  "--ssh=${TS_SSH}"
  "--reset"
)

log "tailscale up çalıştırılıyor"
tailscale up "${UP_FLAGS[@]}" >/dev/null

log "Kurulum tamamlandı"
tailscale status || true
