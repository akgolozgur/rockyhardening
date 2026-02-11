#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/rockyhardening}"
ALLOW_SSH_SUBNET="${ALLOW_SSH_SUBNET:-}"
ALLOW_SSH_LOCKOUT_RISK="${ALLOW_SSH_LOCKOUT_RISK:-false}"

# Rocky Linux 9.7 minimal için savunma amaçlı baseline remediation script'i.
# Amaç: sistemin mevcut güvenlik seviyesini yükseltmek, bilinen zafiyetleri
# paket güncellemesi + güvenli varsayılanlar ile azaltmak.

log() {
  printf '[%s] %s\n' "$(date +'%F %T')" "$*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Bu script root ile çalışmalıdır." >&2
    exit 1
  fi
}

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    install -d -m 0700 "${BACKUP_DIR}"
    cp -a "$f" "${BACKUP_DIR}/$(basename "$f").bak.$(date +%F-%H%M%S)"
  fi
}

set_or_append_kv() {
  local file="$1" key="$2" value="$3"
  if grep -qE "^${key}\s*=" "$file"; then
    sed -ri "s|^${key}\s*=.*|${key} = ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >>"$file"
  fi
}

detect_primary_interface() {
  ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}'
}

apply_updates() {
  log "Dnf metadata yenileniyor"
  dnf -y makecache >/dev/null

  log "Güvenlik odaklı tüm güncellemeler uygulanıyor"
  dnf -y upgrade --refresh >/dev/null

  log "dnf-automatic yükleniyor ve günlük update timer etkinleştiriliyor"
  dnf -y install dnf-automatic >/dev/null
  backup_file /etc/dnf/automatic.conf
  set_or_append_kv /etc/dnf/automatic.conf apply_updates yes
  set_or_append_kv /etc/dnf/automatic.conf upgrade_type security
  systemctl enable --now dnf-automatic.timer >/dev/null
}

install_defensive_tooling() {
  log "Temel güvenlik paketleri yükleniyor"
  dnf -y install \
    openssh-server firewalld audit rsyslog aide chrony policycoreutils-python-utils \
    sudo passwd cracklib libpwquality authselect setroubleshoot-server openscap-scanner scap-security-guide >/dev/null
}

configure_auth_and_crypto() {
  authselect select sssd with-faillock with-mkhomedir --force >/dev/null || true
  update-crypto-policies --set FUTURE >/dev/null || true
}

harden_password_policy() {
  log "Parola politikası sertleştiriliyor"

  backup_file /etc/security/pwquality.conf
  cat >/etc/security/pwquality.conf <<'PWQ'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4
maxrepeat = 2
maxclassrepeat = 3
gecoscheck = 1
dictcheck = 1
enforcing = 1
PWQ

  backup_file /etc/login.defs

  if grep -q '^PASS_MAX_DAYS' /etc/login.defs; then
    sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
  else
    echo 'PASS_MAX_DAYS   90' >>/etc/login.defs
  fi
  if grep -q '^PASS_MIN_DAYS' /etc/login.defs; then
    sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
  else
    echo 'PASS_MIN_DAYS   1' >>/etc/login.defs
  fi
  if grep -q '^PASS_WARN_AGE' /etc/login.defs; then
    sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
  else
    echo 'PASS_WARN_AGE   14' >>/etc/login.defs
  fi
  if grep -q '^UMASK' /etc/login.defs; then
    sed -ri 's/^UMASK.*/UMASK           027/' /etc/login.defs
  else
    echo 'UMASK           027' >>/etc/login.defs
  fi
}

has_usable_authorized_keys() {
  local auth_file line tmp_key
  while IFS= read -r auth_file; do
    [[ -f "${auth_file}" ]] || continue
    while IFS= read -r line; do
      [[ -n "${line}" ]] || continue
      [[ "${line}" =~ ^[[:space:]]*# ]] && continue
      if [[ "${line}" =~ ^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-(ed25519|rsa))[[:space:]] ]]; then
        return 0
      fi
      tmp_key="$(awk '{print $2}' <<<"${line}")"
      if [[ -n "${tmp_key}" ]] && grep -Eq '^[A-Za-z0-9+/]+={0,3}$' <<<"${tmp_key}"; then
        return 0
      fi
    done <"${auth_file}"
  done < <(find /root/.ssh /home -maxdepth 3 -type f -name authorized_keys 2>/dev/null)

  return 1
}

ensure_ssh_key_access() {
  if has_usable_authorized_keys; then
    return 0
  fi

  if [[ "${ALLOW_SSH_LOCKOUT_RISK}" == "true" ]]; then
    log "UYARI: Anahtar bulunamadı ama ALLOW_SSH_LOCKOUT_RISK=true olduğu için parola SSH kapatılmaya devam edilecek"
    return 0
  fi

  echo "HATA: Geçerli bir SSH authorized_keys bulunamadı." >&2
  echo "LOCKOUT riskini engellemek için PasswordAuthentication kapatılmayacak." >&2
  return 1
}

harden_sshd() {
  log "SSHD hardening uygulanıyor"

  install -d -m 0755 /etc/ssh/sshd_config.d

  local disable_password_auth="false"
  if ensure_ssh_key_access; then
    disable_password_auth="true"
  fi

  backup_file /etc/ssh/sshd_config

  if [[ "${disable_password_auth}" == "true" ]]; then
    cat >/etc/ssh/sshd_config.d/99-rocky97-hardening.conf <<'SSHD'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
SSHD
  else
    cat >/etc/ssh/sshd_config.d/99-rocky97-hardening.conf <<'SSHD'
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
SSHD
    log "Uyarı: SSH lockout riskine karşı PasswordAuthentication açık bırakıldı"
  fi

  sshd -t
  systemctl enable --now sshd >/dev/null
  systemctl reload sshd >/dev/null || true
}

configure_firewalld() {
  local iface

  log "firewalld varsayılanları sıkılaştırılıyor"
  systemctl enable --now firewalld >/dev/null
  firewall-cmd --permanent --set-default-zone=drop >/dev/null

  if [[ -n "${ALLOW_SSH_SUBNET}" ]]; then
    local ssh_rule
    ssh_rule="rule family=ipv4 source address=${ALLOW_SSH_SUBNET} service name=ssh accept"
    firewall-cmd --permanent --query-rich-rule="${ssh_rule}" >/dev/null || \
      firewall-cmd --permanent --add-rich-rule="${ssh_rule}" >/dev/null
  else
    firewall-cmd --permanent --zone=drop --add-service=ssh >/dev/null
  fi

  iface="$(detect_primary_interface || true)"
  if [[ -n "${iface}" ]]; then
    firewall-cmd --permanent --zone=drop --add-interface="${iface}" >/dev/null || true
  fi

  firewall-cmd --reload >/dev/null
}

enforce_selinux() {
  log "SELinux enforcing yapılıyor"
  backup_file /etc/selinux/config
  sed -ri 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  setenforce 1 || true
}

kernel_and_network_hardening() {
  log "Kernel/sysctl hardening uygulanıyor"
  cat >/etc/sysctl.d/99-rocky97-hardening.conf <<'SYSCTL'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
SYSCTL
  sysctl --system >/dev/null
}

disable_unused_fs_modules() {
  log "Nadiren kullanılan FS modülleri kapatılıyor"
  cat >/etc/modprobe.d/99-rocky97-hardening.conf <<'MODS'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
MODS
}

audit_baseline() {
  log "auditd baseline kuralı yazılıyor"
  cat >/etc/audit/rules.d/99-rocky97-hardening.rules <<'AUDIT'
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc
AUDIT
  systemctl enable --now auditd >/dev/null
  augenrules --load >/dev/null || true
}

aide_init_if_needed() {
  log "AIDE etkinleştiriliyor"
  systemctl enable --now rsyslog >/dev/null
  if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
    aide --init >/dev/null || true
    if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
      mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
  fi
}

remove_risky_services() {
  log "Minimal sistemde gereksiz olabilecek ağ servisleri kapatılıyor"
  for svc in avahi-daemon cups rpcbind nfs-server; do
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "${svc}.service"; then
      systemctl disable --now "${svc}.service" >/dev/null || true
    fi
  done
}

main() {
  require_root
  install_defensive_tooling
  apply_updates
  configure_auth_and_crypto
  harden_password_policy
  harden_sshd
  configure_firewalld
  enforce_selinux
  kernel_and_network_hardening
  disable_unused_fs_modules
  audit_baseline
  aide_init_if_needed
  remove_risky_services

  log "Remediation tamamlandı. Kernel/SELinux değişiklikleri için reboot önerilir."
}

main "$@"
