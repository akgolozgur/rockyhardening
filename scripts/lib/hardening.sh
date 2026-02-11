#!/usr/bin/env bash
set -euo pipefail


LAB_ADMIN_USER="${LAB_ADMIN_USER:-albertepstein}"

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
SUDO
  chmod 0440 /etc/sudoers.d/80-training-main-admin
  visudo -cf /etc/sudoers >/dev/null
}

log() {
  printf '[%s] %s\n' "$(date +'%F %T')" "$*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Bu script root ile çalışmalıdır." >&2
    exit 1
  fi
}

install_base_packages() {
  dnf -y install policycoreutils-python-utils firewalld audit rsyslog aide openssh-server sudo curl >/dev/null
}

apply_sysctl_baseline() {
  cat >/etc/sysctl.d/99-training-hardening.conf <<'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTL
  sysctl --system >/dev/null
}

harden_ssh() {
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
  systemctl enable --now sshd
  systemctl reload sshd || true
}

configure_firewall() {
  systemctl enable --now firewalld
  firewall-cmd --permanent --set-default-zone=public >/dev/null
  firewall-cmd --permanent --add-service=ssh >/dev/null
  firewall-cmd --reload >/dev/null
}

lock_unused_filesystems() {
  cat >/etc/modprobe.d/99-training-hardening.conf <<'MODS'
install cramfs /bin/true
install squashfs /bin/true
install udf /bin/true
MODS
}

baseline_hardening() {
  log "Paketler yükleniyor"
  install_base_packages

  log "sysctl baseline uygulanıyor"
  apply_sysctl_baseline

  log "Ana yönetici kullanıcı hazırlanıyor"
  ensure_main_admin_user

  log "SSH hardening uygulanıyor"
  harden_ssh

  log "firewalld yapılandırılıyor"
  configure_firewall

  log "kullanılmayan filesystem modülleri kapatılıyor"
  lock_unused_filesystems
}
