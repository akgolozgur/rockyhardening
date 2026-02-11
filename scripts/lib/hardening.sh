#!/usr/bin/env bash
set -euo pipefail

LAB_ADMIN_USER="${LAB_ADMIN_USER:-albertepstein}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/rockyhardening}"
ALLOW_SSH_SUBNET="${ALLOW_SSH_SUBNET:-}"

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

ensure_main_admin_user() {
  if ! id -u "${LAB_ADMIN_USER}" &>/dev/null; then
    useradd -m -G wheel "${LAB_ADMIN_USER}"
  fi

  install -d -m 0700 -o "${LAB_ADMIN_USER}" -g "${LAB_ADMIN_USER}" "/home/${LAB_ADMIN_USER}/.ssh"
  touch "/home/${LAB_ADMIN_USER}/.ssh/authorized_keys"
  chown "${LAB_ADMIN_USER}:${LAB_ADMIN_USER}" "/home/${LAB_ADMIN_USER}/.ssh/authorized_keys"
  chmod 0600 "/home/${LAB_ADMIN_USER}/.ssh/authorized_keys"

  cat >/etc/sudoers.d/80-training-main-admin <<SUDO
${LAB_ADMIN_USER} ALL=(ALL) ALL
Defaults use_pty
Defaults log_output
Defaults logfile="/var/log/sudo.log"
SUDO
  chmod 0440 /etc/sudoers.d/80-training-main-admin
  visudo -cf /etc/sudoers >/dev/null
}

install_base_packages() {
  dnf -y install policycoreutils-python-utils firewalld audit rsyslog aide openssh-server sudo curl authselect >/dev/null
}

apply_auth_and_crypto() {
  authselect select sssd with-faillock with-mkhomedir --force >/dev/null || true
  update-crypto-policies --set FUTURE >/dev/null || true
}

apply_sysctl_baseline() {
  cat >/etc/sysctl.d/99-training-hardening.conf <<'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL
  sysctl --system >/dev/null
}

harden_ssh() {
  backup_file /etc/ssh/sshd_config
  install -d -m 0755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/10-training-hardening.conf <<'SSHD'
PasswordAuthentication no
PermitRootLogin no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
AllowAgentForwarding no
AllowTcpForwarding no
SSHD
  sshd -t
  systemctl enable --now sshd >/dev/null
  systemctl reload sshd >/dev/null || true
}

detect_primary_interface() {
  ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}'
}

configure_firewall() {
  local iface
  systemctl enable --now firewalld >/dev/null
  firewall-cmd --permanent --set-default-zone=public >/dev/null
  firewall-cmd --permanent --remove-service=cockpit >/dev/null || true
  firewall-cmd --permanent --remove-service=dhcpv6-client >/dev/null || true

  if [[ -n "${ALLOW_SSH_SUBNET}" ]]; then
    firewall-cmd --permanent --remove-service=ssh >/dev/null || true
    firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ALLOW_SSH_SUBNET} service name=ssh accept" >/dev/null || true
  else
    firewall-cmd --permanent --add-service=ssh >/dev/null
  fi

  iface="$(detect_primary_interface || true)"
  if [[ -n "${iface}" ]]; then
    firewall-cmd --permanent --zone=public --add-interface="${iface}" >/dev/null || true
  fi

  firewall-cmd --reload >/dev/null
}

lock_unused_filesystems() {
  cat >/etc/modprobe.d/99-training-hardening.conf <<'MODS'
install cramfs /bin/true
install squashfs /bin/true
install udf /bin/true
MODS
}

enforce_critical_permissions() {
  chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers
  chmod 0644 /etc/passwd /etc/group
  chmod 000 /etc/shadow /etc/gshadow || chmod 0600 /etc/shadow /etc/gshadow
  chmod 0440 /etc/sudoers
}

baseline_hardening() {
  log "Paketler yükleniyor"
  install_base_packages

  log "Ana yönetici kullanıcı hazırlanıyor"
  ensure_main_admin_user

  log "auth + crypto politikaları uygulanıyor"
  apply_auth_and_crypto

  log "sysctl baseline uygulanıyor"
  apply_sysctl_baseline

  log "SSH hardening uygulanıyor"
  harden_ssh

  log "firewalld yapılandırılıyor"
  configure_firewall

  log "kullanılmayan filesystem modülleri kapatılıyor"
  lock_unused_filesystems

  enforce_critical_permissions
}
