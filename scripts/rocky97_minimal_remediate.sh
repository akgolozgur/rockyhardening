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
  dnf -y makecache >/dev/null
  dnf -y upgrade --refresh >/dev/null
  dnf -y install dnf-automatic >/dev/null
  backup_file /etc/dnf/automatic.conf
  set_or_append_kv /etc/dnf/automatic.conf apply_updates yes
  set_or_append_kv /etc/dnf/automatic.conf upgrade_type security

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

  dnf -y install \
    openssh-server firewalld audit rsyslog aide chrony policycoreutils-python-utils \
    sudo passwd cracklib libpwquality authselect setroubleshoot-server openscap-scanner scap-security-guide >/dev/null
}

configure_auth_and_crypto() {
  authselect select sssd with-faillock with-mkhomedir --force >/dev/null || true
  update-crypto-policies --set FUTURE >/dev/null || true
}

harden_password_policy() {

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

  if grep -q '^PASS_MAX_DAYS' /etc/login.defs; then
    sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
  else
    echo 'PASS_MAX_DAYS   90' >> /etc/login.defs
  fi
  if grep -q '^PASS_MIN_DAYS' /etc/login.defs; then
    sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
  else
    echo 'PASS_MIN_DAYS   1' >> /etc/login.defs
  fi
  if grep -q '^PASS_WARN_AGE' /etc/login.defs; then
    sed -ri 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
  else
    echo 'PASS_WARN_AGE   14' >> /etc/login.defs
  fi
  if grep -q '^UMASK' /etc/login.defs; then
    sed -ri 's/^UMASK.*/UMASK           027/' /etc/login.defs
  else
    echo 'UMASK           027' >> /etc/login.defs
  fi
}

harden_sshd() {
  ensure_ssh_key_access
  backup_file /etc/ssh/sshd_config

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


has_usable_authorized_keys() {
  local auth_file line tmp_key
  while IFS= read -r -d '' auth_file; do
    [[ -s "${auth_file}" ]] || continue

    while IFS= read -r line || [[ -n "${line}" ]]; do
      [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue

      tmp_key="$(mktemp)"
      printf '%s\n' "${line}" >"${tmp_key}"
      if ssh-keygen -l -f "${tmp_key}" >/dev/null 2>&1; then
        rm -f "${tmp_key}"
        return 0
      fi
      rm -f "${tmp_key}"
    done <"${auth_file}"
  done < <(find /root /home -mindepth 2 -maxdepth 3 -type f -path '*/.ssh/authorized_keys' -print0 2>/dev/null)

  return 1
}

ensure_ssh_key_access() {
  if has_usable_authorized_keys; then
    return 0
  fi

  if [[ "${ALLOW_SSH_LOCKOUT_RISK}" == "true" ]]; then
    log "UYARI: authorized_keys bulunamadı, ALLOW_SSH_LOCKOUT_RISK=true ile devam ediliyor"
    return 0
  fi

  echo "HATA: PasswordAuthentication=no uygulanmadan önce en az bir geçerli authorized_keys girdisi bulunmalı." >&2
  echo "İstisnai olarak devam etmek için ALLOW_SSH_LOCKOUT_RISK=true ayarlayın." >&2
  exit 1
}

configure_firewalld() {
  local iface ssh_restrict_rule
  systemctl enable --now firewalld >/dev/null
  firewall-cmd --permanent --set-default-zone=public >/dev/null
  firewall-cmd --permanent --remove-service=cockpit >/dev/null || true
  firewall-cmd --permanent --remove-service=dhcpv6-client >/dev/null || true

  if [[ -n "${ALLOW_SSH_SUBNET}" ]]; then
    ssh_restrict_rule="rule family=ipv4 source address=${ALLOW_SSH_SUBNET} service name=ssh accept"
    if ! firewall-cmd --permanent --query-rich-rule="${ssh_restrict_rule}" >/dev/null; then
      firewall-cmd --permanent --add-rich-rule="${ssh_restrict_rule}" >/dev/null
    fi
    firewall-cmd --permanent --remove-service=ssh >/dev/null || true
  else
    firewall-cmd --permanent --add-service=ssh >/dev/null
  fi

  iface="$(detect_primary_interface || true)"
  if [[ -n "${iface}" ]]; then
    firewall-cmd --permanent --zone=public --add-interface="${iface}" >/dev/null || true
  fi


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

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

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

  cat >/etc/audit/rules.d/99-rocky97-hardening.rules <<'AUDIT'
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change

  log "auditd baseline kuralı yazılıyor"
  cat >/etc/audit/rules.d/99-rocky97-hardening.rules <<'AUDIT'

-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc

-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
AUDIT

  backup_file /etc/audit/auditd.conf
  set_or_append_kv /etc/audit/auditd.conf max_log_file 50
  set_or_append_kv /etc/audit/auditd.conf max_log_file_action ROTATE
  set_or_append_kv /etc/audit/auditd.conf space_left_action SYSLOG

  systemctl enable --now auditd >/dev/null
  augenrules --load >/dev/null || true
  chmod 0700 /var/log/audit || true
}

aide_init_if_needed() {
  systemctl enable --now rsyslog >/dev/null
  if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
    nice -n 10 aide --init >/dev/null || true

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


set_critical_permissions() {
  chmod 0644 /etc/passwd /etc/group
  chmod 000 /etc/shadow /etc/gshadow || chmod 0600 /etc/shadow /etc/gshadow
  chmod 0440 /etc/sudoers
  chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers
  if [[ -f /boot/grub2/grub.cfg ]]; then
    chmod 0600 /boot/grub2/grub.cfg
    chown root:root /boot/grub2/grub.cfg
  fi
}

create_rollback_helper() {
  cat >/usr/local/sbin/training-soften.sh <<'SOFTEN'
#!/usr/bin/env bash
set -euo pipefail

echo "[soften] geçici eğitim modu: dmesg erişimi + ASLR kapatma"
sysctl -w kernel.dmesg_restrict=0 >/dev/null
sysctl -w kernel.randomize_va_space=0 >/dev/null
SOFTEN
  chmod 0750 /usr/local/sbin/training-soften.sh
}

run_openscap_eval() {
  local xccdf
  xccdf="/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"
  if [[ -f "${xccdf}" ]]; then
    oscap xccdf eval \
      --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
      --results /var/log/openscap-cis-results.xml \
      --report /var/log/openscap-cis-report.html \
      "${xccdf}" >/dev/null || true
  fi
}

remove_risky_services() {
  local unit
  for unit in avahi-daemon.service cups.service rpcbind.service nfs-server.service telnet.socket tftp.socket; do
    if systemctl list-unit-files --no-legend | awk '{print $1}' | grep -qx "${unit}"; then
      systemctl disable --now "${unit}" >/dev/null || true

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

  log "Paketler yükleniyor"
  install_defensive_tooling
  log "Güncellemeler uygulanıyor"
  apply_updates
  log "Kimlik doğrulama ve kripto politikası uygulanıyor"
  configure_auth_and_crypto
  log "Parola politikası uygulanıyor"
  harden_password_policy
  log "SSH hardening uygulanıyor"
  harden_sshd
  log "Firewall hardening uygulanıyor"
  configure_firewalld
  log "SELinux enforcing ayarlanıyor"
  enforce_selinux
  log "Kernel/sysctl hardening uygulanıyor"
  kernel_and_network_hardening
  log "Kullanılmayan FS modülleri kapatılıyor"
  disable_unused_fs_modules
  log "Audit baseline uygulanıyor"
  audit_baseline
  log "AIDE başlatılıyor"
  aide_init_if_needed
  log "Kritik izinler düzeltiliyor"
  set_critical_permissions
  log "Rollback helper yazılıyor"
  create_rollback_helper
  log "OpenSCAP değerlendirmesi çalıştırılıyor"
  run_openscap_eval
  log "Gereksiz servisler kapatılıyor"

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
