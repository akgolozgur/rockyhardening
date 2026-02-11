# Rocky Hardening Lab — Write-up (Hikayeli Çözüm Yolu)

Bu doküman eğitmen (ana kullanıcı: `albertepstein`) için hazırlanmış örnek bir çözüm yoludur.
Amaç: sistemde yalnızca bilerek bırakılan zafiyetleri katılımcılara avlatmak ve her stage sonunda doğru remediation adımını göstermek.

## Hikaye
Bir siber güvenlik akademisinde, mavi takım eğitmeni `albertepstein` Rocky Linux 9.7 Minimal üzerinde 10 aşamalı bir savunma laboratuvarı kurar.
Altyapı baseline hardening ile sıkılaştırılmıştır; ancak her bölümde öğrenme amaçlı tek bir yanlış yapılandırma bırakılmıştır.
Katılımcılar her bölümde önce keşif yapar, sonra açığı doğrular, ardından düzeltip kanıt üretir.

---

## 0) Başlangıç Kurulumu (Eğitmen)
```bash
sudo bash scripts/rocky97_minimal_remediate.sh
sudo LAB_ADMIN_USER=albertepstein bash scripts/deploy_training_lab.sh --all --profile strict
```

İsteğe bağlı:
```bash
sudo TS_AUTHKEY='<tailscale_auth_key>' bash scripts/install_unattended_tailscale.sh
sudo bash scripts/setup_professional_web443.sh
```

---

## Stage 1 — SSH Anahtar Hijyeni
**Konu:** SSH dosya izinleri

**Beklenen bulgu:** `/home/analyst/.ssh` izinleri gevşek.

**Keşif:**
```bash
namei -l /home/analyst/.ssh
ls -ld /home/analyst/.ssh
ls -l /home/analyst/.ssh/authorized_keys
```

**Düzeltme:**
```bash
chmod 700 /home/analyst/.ssh
chmod 600 /home/analyst/.ssh/authorized_keys
chown -R analyst:analyst /home/analyst/.ssh
```

---

## Stage 2 — Web Header Hardening
**Konu:** HTTP security headers

**Beklenen bulgu:** CSP header eksik.

**Keşif:**
```bash
curl -sI http://127.0.0.1:8080/
```

**Düzeltme (örnek):**
Nginx konfigine CSP eklenir:
```nginx
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
```

---

## Stage 3 — ACL Yanlış Yetkilendirme
**Konu:** Dosya izinleri + ACL

**Beklenen bulgu:** `analytics` grubuna gereksiz okuma ACL'i verilmiş.

**Keşif:**
```bash
getfacl /srv/labdata/customers.csv
```

**Düzeltme:**
```bash
setfacl -x g:analytics /srv/labdata/customers.csv
```

---

## Stage 4 — Sudo Yetki Daraltma
**Konu:** Privilege escalation yüzeyi

**Beklenen bulgu:** `trainee` için wildcard restart izni çok geniş.

**Keşif:**
```bash
sudo -l -U trainee
```

**Düzeltme:**
`/etc/sudoers.d/90-training-stage04` içeriği daraltılır (tek servis, tam path, wildcard yok).

---

## Stage 5 — Systemd Sandboxing
**Konu:** Servis izolasyonu

**Beklenen bulgu:** `training-agent.service` sandbox direktifleri eksik.

**Düzeltme (örnek):**
```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
```

Uygulama:
```bash
systemctl daemon-reload
systemctl restart training-agent.service
```

---

## Stage 6 — Audit Kapsamı
**Konu:** Denetim kayıt bütünlüğü

**Beklenen bulgu:** `/etc/shadow` watch kuralı yok.

**Düzeltme:**
```bash
echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/training.rules
augenrules --load
```

---

## Stage 7 — Ağ Segmentasyonu
**Konu:** East-west erişim daraltma

**Beklenen bulgu:** Source CIDR gereğinden geniş.

**Düzeltme yaklaşımı:**
- `10.77.0.0/24` yerine ihtiyaç duyulan tek host/alt ağ tanımlanır.
- Gerekmeyen port izinleri kaldırılır.

---

## Stage 8 — Container Hardening
**Konu:** Podman runtime güvenliği

**Beklenen bulgu:** `--privileged` kullanılmış.

**Düzeltme yaklaşımı:**
- `--privileged` kaldırılır
- Gerekliyse `--cap-drop ALL` + minimum `--cap-add` uygulanır
- read-only filesystem + seccomp profili değerlendirilir

---

## Stage 9 — Secrets Yönetimi
**Konu:** Hardcoded secret

**Beklenen bulgu:** `API_TOKEN` düz metin dosyada.

**Düzeltme yaklaşımı:**
- Secret manager / env injection / vault
- Token rotate
- Dosya erişimini minimuma indir

---

## Stage 10 — IR / Forensics Hazırlığı
**Konu:** Olay müdahale hazırlığı

**Beklenen bulgu:** Toplanan arşivlerin integrity doğrulaması yok.

**Düzeltme yaklaşımı:**
- hash üretimi (`sha256sum`)
- write-once hedef / immutable storage
- imzalı log zinciri

---

## Eğitmen Akışı (öneri)
1. Stage açılır.
2. Katılımcı keşif komutları ile bulgu üretir.
3. Tespit edilen riskin etkisini açıklar.
4. Remediation uygular.
5. `scripts/validate_stage.sh <n>` ve ek komutlarla kanıt toplar.
6. Bir sonraki stage'e geçilir.

## Not
- `albertepstein` ana yönetici kullanıcıdır; deploy sırasında otomatik oluşturulur.
- “Sıfır açık” bir durum statik değildir; düzenli güncelleme + tarama + doğrulama şarttır.
