# Rocky Linux 10 Aşamalı Siber Güvenlik Eğitim Laboratuvarı

Bu repo, **Rocky Linux üzerinde savunma odaklı eğitim** için hazırlanmış 10 aşamalı bir laboratuvar iskeleti sağlar.

## Hedef
- Tüm VM'lerde önce ortak bir **hardening baseline** uygulanır.
- Her aşamada yalnızca **eğitim amacıyla kontrollü olarak eklenen tek bir zafiyet/yanlış yapılandırma** bulunur.
- Her aşama farklı bir konu ve zorluk düzeyi öğretir.

> Not: “Tamamen açıksız sistem” pratikte garanti edilemez. Bu yapı, saldırı yüzeyini minimuma indirip sadece eğitimde kullanacağınız senaryoları bırakmak için tasarlanmıştır.

## Dizin Yapısı
- `scripts/deploy_training_lab.sh`: Ana orkestrasyon script'i
- `scripts/lib/hardening.sh`: Ortak hardening fonksiyonları
- `scripts/stages/`: 10 aşamanın her biri için stage script'leri
- `scripts/rocky97_minimal_remediate.sh`: Rocky Linux 9.7 Minimal için ek remediation/hardening script'i
- `scripts/install_unattended_tailscale.sh`: Unattended Tailscale kurulum script'i
- `scripts/setup_professional_web443.sh`: 443 üzerinde hardened NGINX web servisi kurulum script'i
- `docs/writeup_albertepstein.md`: Hikayeli çözüm yolu ve eğitmen notları


## Ana Kullanıcı
- Varsayılan ana yönetici kullanıcı: `albertepstein`
- `deploy_training_lab.sh` çalışırken bu kullanıcı otomatik oluşturulur ve sudo yetkisi verilir.
- İsterseniz farklı kullanıcı için: `LAB_ADMIN_USER=<kullanici>` environment variable kullanabilirsiniz.

## Hızlı Kullanım
```bash
sudo bash scripts/deploy_training_lab.sh --stage 1
sudo bash scripts/deploy_training_lab.sh --stage 5 --profile strict
sudo bash scripts/deploy_training_lab.sh --all
```

## Aşamalar (Özet)
1. SSH temel güvenlik ve anahtar yönetimi
2. Web sunucusu sertleştirme ve başlıklar
3. Dosya izinleri ve yanlış ACL avı
4. Sudoers ve ayrıcalık yükseltme kontrolleri
5. Servis hardening (systemd sandboxing)
6. Log bütünlüğü ve denetim (auditd)
7. Ağ filtreleme ve east-west segment yaklaşımı
8. Container hardening (podman)
9. Secrets yönetimi ve rotasyon
10. Incident response + forensics hazırlığı

## Eğitim Akışı Önerisi
1. Stage deploy edilir.
2. Katılımcı önce keşif yapar.
3. Yanlış yapılandırmayı tespit eder.
4. Düzeltmeyi uygular ve doğrulama script'i çalıştırır.
5. Sonraki aşamaya geçilir.

## Güvenlik Sınırları
- Bu repo **yalnızca izole eğitim lab ortamı** için kullanılmalıdır.
- İnternete açık prod sistemlerde doğrudan kullanılmamalıdır.

## Rocky Linux 9.7 Minimal Ek Remediation
Eğer lab'i Rocky Linux 9.7 Minimal üzerinde kuruyorsanız, önce aşağıdaki script ile sistem baseline'ını sıkılaştırın:

```bash
sudo bash scripts/rocky97_minimal_remediate.sh
```

Bu script; paket güncellemeleri, SELinux enforcing, SSH/firewalld sertleştirme, parola politikası, sysctl hardening, auditd ve AIDE başlangıç ayarlarını uygular.


## Unattended Tailscale (Eğitmen Erişimi)
Eğitimi uzaktan kontrol etmek için Tailscale kurulumunu non-interactive şekilde yapabilirsiniz:

```bash
sudo TS_AUTHKEY='<tailscale_auth_key>' bash scripts/install_unattended_tailscale.sh
```

Veya stage deploy ile birlikte:

```bash
sudo TS_AUTHKEY='<tailscale_auth_key>' bash scripts/deploy_training_lab.sh --all --install-tailscale
```

> Güvenlik notu: Auth key'i script dosyalarına yazmayın, git'e commit etmeyin. Mümkünse kısa ömürlü (ephemeral/reusable policy'nize uygun) key kullanın ve düzenli rotate edin.


## 443 Web Servisi (Hardened / Professional Baseline)
Aşağıdaki script ile 443/tcp üzerinde hardened NGINX servis kurulabilir:

```bash
sudo bash scripts/setup_professional_web443.sh
```

Deploy ile birlikte çalıştırma:

```bash
sudo bash scripts/deploy_training_lab.sh --all --setup-web443
```

Sadece eğitim için kontrollü tek açıklık bırakmak isterseniz:

```bash
sudo bash scripts/deploy_training_lab.sh --all --setup-web443 --web443-intentional-vuln true
```

> Not: "bilinen hiçbir açık yok" ifadesi hiçbir yazılım için kalıcı olarak garanti edilemez. Bu yaklaşım saldırı yüzeyini azaltır; açık yönetimi için patching + sürekli tarama gerekir.


## Write-up
Hikayeli çözüm path dokümanı: `docs/writeup_albertepstein.md`
