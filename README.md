# Web Güvenlik Radarı 🛡️

> **Pasif Güvenlik Başlıkları, DoH DNS & E-posta Savunma Röntgeni**  
> Sıfır WAF & Abuse Riski • %100 İstemci Taraflı (Zero-Backend) • GitHub Pages Uyumlu

[![GitHub Pages](https://img.shields.io/badge/Demo-GitHub%20Pages-orange?style=flat-square)](https://melihkarasu.github.io/web-guvenlik-radari/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Design: Mistral AI](https://img.shields.io/badge/Design-Mistral%20AI-fa520f?style=flat-square)](https://mistral.ai)

---

## 📌 Nedir ve Neden Geliştirildi?

Geleneksel web güvenlik tarayıcıları (aktif DAST ve vulnerability scanner araçları), hedef web sitelerine binlerce saldırı payload'ı göndererek güvenlik açıklarını bulmaya çalışır. Ancak üçüncü parti veya canlı sistemlerde bu tür aktif taramalar:
1. **WAF ve IPS Engelleri:** Cloudflare, AWS WAF veya Fail2ban tarafından tarayıcı IP'sinin anında engellenmesine,
2. **Abuse ve Yasal Sorunlar:** Yetkisiz sistemlere yapılan testlerin siber saldırı olarak algılanıp sunucu sağlayıcısına şikayet düşmesine yol açar.

**Web Güvenlik Radarı**, bu riski **tamamen sıfıra indiren pasif bir güvenlik denetim aracıdır**. Tıpkı bir web tarayıcısının sayfayı ziyaret etmesi gibi, hedefe hiçbir zararlı payload göndermeden:
- **CORS-Açık DNS-over-HTTPS (DoH)** üzerinden alan adının e-posta ve alan adı kalkanlarını (DMARC, SPF, DNSSEC, CAA),
- **HTTP Güvenlik Başlıklarını** (CSP, HSTS, X-Frame-Options, MIME Sniffing, Referrer Policy) ve bilgi ifşası sızıntılarını (`Server`, `X-Powered-By`),
- Kapsamlı **OWASP & Modern Mimari Kontrol Listesi** standartlarını analiz eder.

---

## 🚀 Temel Yetenekler

### 1. 🛡️ HTTP Güvenlik Başlıkları Analizi
* **Content-Security-Policy (CSP):** XSS ve veri enjeksiyonu savunması; `unsafe-inline` ve `unsafe-eval` zayıflık tespiti.
* **Strict-Transport-Security (HSTS):** SSL-stripping engeli, `max-age` süresi, `includeSubDomains` ve `preload` kontrolü.
* **X-Frame-Options:** Clickjacking (tıklama sahtekarlığı) ve yetkisiz iframe gömme engeli (`DENY` / `SAMEORIGIN`).
* **X-Content-Type-Options:** `nosniff` başlığı ile kötü amaçlı MIME türü tahminlerinin engellenmesi.
* **Referrer-Policy:** Hassas URL parametrelerinin dış sitelere sızdırılmaması.
* **Permissions-Policy:** Kamera, mikrofon ve konum gibi donanım sensörlerinin kısıtlanması.

### 2. 🌐 DoH DNS & E-posta Sahteciliği Savunması
* **DMARC Kalkanı (`_dmarc.{domain}`):** Alan adı adına sahte e-posta gönderimini engelleyen kural seviyesi (`p=reject`, `p=quarantine`, `p=none`).
* **SPF Doğrulaması (`v=spf1`):** Yetkili posta sunucularının tanımlanması ve katı kural (`-all` vs `~all`) analizi.
* **DNSSEC Desteği:** DNS önbellek zehirlenmesine (DNS Poisoning) karşı dijital imza doğrulaması (`AD=1`).
* **CAA Kayıtları:** Yalnızca onaylı Sertifika Yetkililerinin (CA) SSL üretebilmesi için yetkilendirme kontrolü.
* **IPv6 Readiness:** AAAA kayıtları ile yeni nesil ağ protokolü hazırbulunuşluğu.

### 3. 📋 Derin Header Röntgeni (cURL Yapıştırma Modu)
* Geliştiriciler terminalden aldıkları `curl -I https://site.com` çıktısını veya tarayıcı Response Headers bloğunu doğrudan yapıştırarak 1 saniyede derin güvenlik puanı alabilir.

### 4. ⚙️ Anında Çözüm Kodları (Nginx & Apache)
* Tespit edilen her eksik güvenlik başlığı için tek tıkla kopyalanabilen hazır **Nginx** (`add_header ...`) ve **Apache** (`Header set ...`) konfigürasyon kodları sunulur.

### 5. 📥 Markdown Raporu Dışa Aktarma
* Denetim sonuçları, skor, zafiyetler ve çözüm kodları tek tıkla `.md` formatında indirilebilir.

---

## 🛠️ Mimari ve Teknolojiler

- **%100 Sıfır Backend (Zero-Backend):** Sunucuya ihtiyaç duymaz, API anahtarı veya veritabanı gerektirmez. Doğrudan GitHub Pages üzerinde çalışır.
- **Tasarım:** [Mistral AI Tasarım Sistemi](https://mistral.ai) (Newsreader, Inter, JetBrains Mono fontları ve zarif sunset renk paleti).
- **DNS Sağlayıcıları:** Cloudflare DoH (`cloudflare-dns.com`) ve Google DoH (`dns.google`).

---

## 💻 Yerel Ortamda Çalıştırma

Projeyi yerel makinenizde çalıştırmak için herhangi bir paket yöneticisi kurmanıza gerek yoktur:

```bash
git clone https://github.com/melihkarasu/web-guvenlik-radari.git
cd web-guvenlik-radari

# Herhangi bir yerel statik sunucu ile açabilirsiniz:
python3 -m http.server 8080
# Tarayıcınızda açın: http://localhost:8080
```

---

## 🏆 Krediler & Referanslar

Bu projenin kural seti ve denetim metodolojisi aşağıdaki açık kaynak güvenlik projelerinden ilham almıştır:
- **[usestrix/strix](https://github.com/usestrix/strix):** Otonom AI penetrasyon testi ve dinamik güvenlik ajanı.
- **[ersinkoc/security-check](https://github.com/ersinkoc/security-check):** OWASP Top 10 ve statik kod denetimi standartları.
- **[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill):** Kanıt odaklı güvenlik denetim metodolojisi.
- **[VibeCodedApps](https://app.melihkarasu.com):** Mikro uygulama portföyü ve üretim ortamı mimarisi.

---

## 📄 Lisans
Bu proje [MIT Lisansı](LICENSE) altında açık kaynak olarak yayınlanmıştır.
