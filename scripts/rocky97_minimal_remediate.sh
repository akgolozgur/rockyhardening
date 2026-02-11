#!/usr/bin/env bash
set -euo pipefail

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
    cp -a "$f" "${f}.bak.$(date +%F-%H%M%S)"
  fi
}

apply_updates() {
  log "Dnf metadata yenileniyor"
  dnf -y makecache >/dev/null

  log "Güvenlik odaklı tüm güncellemeler uygulanıyor"
  dnf -y upgrade --refresh >/dev/null

  log "dnf-automatic yükleniyor ve günlük update timer etkinleştiriliyor"
  dnf -y install dnf-automatic >/dev/null
  backup_file /etc/dnf/automatic.conf
  sed -ri 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/dnf/automatic.conf
  sed -ri 's/^upgrade_type\s*=.*/upgrade_type = security/' /etc/dnf/automatic.conf
  systemctl enable --now dnf-automatic.timer >/dev/null
}

install_defensive_tooling() {
  log "Temel güvenlik paketleri yükleniyor"
  dnf -y install \
    openssh-server firewalld audit rsyslog aide chrony policycoreutils-python-utils \
    sudo passwd cracklib libpwquality >/dev/null
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
  sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
  sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
  sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
  sed -ri 's/^UMASK.*/UMASK           027/' /etc/login.defs
}

harden_sshd() {
  log "SSHD hardening uygulanıyor"
  install -d -m 0755 /etc/ssh/sshd_config.d
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

  sshd -t
  systemctl enable --now sshd >/dev/null
  systemctl reload sshd >/dev/null || true
}

configure_firewalld() {
  log "firewalld varsayılanları sıkılaştırılıyor"
  systemctl enable --now firewalld >/dev/null
  firewall-cmd --permanent --set-default-zone=drop >/dev/null
  firewall-cmd --permanent --zone=drop --add-service=ssh >/dev/null
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
