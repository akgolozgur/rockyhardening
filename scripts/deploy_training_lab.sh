#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hardening.sh
source "${SCRIPT_DIR}/lib/hardening.sh"

PROFILE="standard"
STAGE=""
RUN_ALL="false"
INSTALL_TS="false"
TS_AUTHKEY="${TS_AUTHKEY:-}"
SETUP_WEB443="false"
WEB443_INTENTIONAL_VULN="false"

usage() {
  cat <<'USAGE'
Kullanım:
  bash scripts/deploy_training_lab.sh --stage <1-10> [--profile standard|strict]
  bash scripts/deploy_training_lab.sh --all [--profile standard|strict] [--install-tailscale] [--setup-web443]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)
      STAGE="${2:-}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:-standard}"
      shift 2
      ;;
    --all)
      RUN_ALL="true"
      shift
      ;;
    --install-tailscale)
      INSTALL_TS="true"
      shift
      ;;
    --tailscale-auth-key)
      TS_AUTHKEY="${2:-}"
      shift 2
      ;;
    --setup-web443)
      SETUP_WEB443="true"
      shift
      ;;
    --web443-intentional-vuln)
      WEB443_INTENTIONAL_VULN="${2:-false}"
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
baseline_hardening

if [[ "${PROFILE}" == "strict" ]]; then
  log "Strict profil: faillock + mkhomedir + güçlü umask aktif"
  authselect select sssd with-faillock with-mkhomedir --force >/dev/null || true
  if grep -q '^UMASK' /etc/login.defs; then
    sed -ri 's/^UMASK.*/UMASK 027/' /etc/login.defs
  else
    echo 'UMASK 027' >> /etc/login.defs
  fi
fi

run_stage() {
  local idx="$1"
  local stage_file
  stage_file=$(printf '%s/stages/%02d_*.sh' "${SCRIPT_DIR}" "${idx}")

  if compgen -G "${stage_file}" >/dev/null; then
    local real_file
    real_file=$(compgen -G "${stage_file}" | head -n1)
    log "Stage ${idx} uygulanıyor: ${real_file##*/}"
    bash "${real_file}"
  else
    echo "Stage bulunamadı: ${idx}" >&2
    exit 1
  fi
}

if [[ "${RUN_ALL}" == "true" ]]; then
  for i in $(seq 1 10); do
    run_stage "${i}"
  done
elif [[ -n "${STAGE}" ]]; then
  if ! [[ "${STAGE}" =~ ^([1-9]|10)$ ]]; then
    echo "--stage 1-10 aralığında olmalı" >&2
    exit 1
  fi
  run_stage "${STAGE}"
else
  usage
  exit 1
fi


if [[ "${SETUP_WEB443}" == "true" ]]; then
  log "443 web servisi kuruluyor"
  INTENTIONAL_VULN="${WEB443_INTENTIONAL_VULN}" bash "${SCRIPT_DIR}/setup_professional_web443.sh"
fi

if [[ "${INSTALL_TS}" == "true" ]]; then
  log "Unattended tailscale kurulumu başlatılıyor"
  if [[ -z "${TS_AUTHKEY}" ]]; then
    echo "Tailscale için TS_AUTHKEY env veya --tailscale-auth-key gerekli" >&2
    exit 1
  fi
  TS_AUTHKEY="${TS_AUTHKEY}" bash "${SCRIPT_DIR}/install_unattended_tailscale.sh"
fi

log "Tamamlandı"
