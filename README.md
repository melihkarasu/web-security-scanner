# Web Security Scanner 🛡️

> **Kapsamlı Web Güvenlik Denetim Aracı:** Pasif Tarama + Derin Analiz + SAST (Kaynak Kod) + Aktif Test  
> Hibrit Mimari: Canlı Demo (GitHub Pages) + Bağımsız Sıfır-Bağımlılık Yerel Sunucu (Local Mode)

[![GitHub Pages Demo](https://img.shields.io/badge/Canlı%20Demo-GitHub%20Pages-orange?style=flat-square)](https://melihkarasu.github.io/web-security-scanner/)
[![Local Mode](https://img.shields.io/badge/Local%20Mode-Python%203%20Stdlib-emerald?style=flat-square)](#-2-yerel-sunucu-modu-tam-ve-otomatik-tarama)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Design: Mistral AI](https://img.shields.io/badge/Design-Mistral%20AI-fa520f?style=flat-square)](https://mistral.ai)

---

## ⚖️ YASAL SORUMLULUK VE ETİK KULLANIM UYARISI

> **DİKKAT — KULLANICI SORUMLULUĞU:**  
> 1. Bu yazılım, **yalnızca sahibi olduğunuz, yönettiğiniz veya test etmek için açık yazılı izne sahip olduğunuz** sistemlerin güvenlik duruşunu denetlemek amacıyla geliştirilmiştir.
> 2. **Aktif Test Modu (Faz 3)** hedef sisteme gerçek HTTP istekleri gönderir. Arayüzdeki **etik onay beyanı** zorunludur; onaysız hiçbir aktif istek gönderilmez. İstekler rate-limitlidir (1.5 sn/istek, tarama başına maks. 60 istek) ancak bu, yetki gerekliliğini ortadan kaldırmaz.
> 3. **Yerel (Local) Modda Çalışırken:** Yazılım kullanıcının kendi yerel makinesinden (`127.0.0.1`) çalışır ve gönderilen tüm HTTP istekleri **kullanıcının kendi IP adresinden** çıkar.
> 4. İzniniz olmayan üçüncü parti web sitelerini, kamu kurumlarını, bankaları veya şirket altyapılarını hedef almak; otomatize veya sistematik döngülerle istek göndererek servisleri meşgul etmek (DDoS/Brute-force benzeri algılanma riski):
>    - Hedef sistemlerin **WAF (Web Application Firewall)** ve IDS/IPS mekanizmaları tarafından **IP adresinizin kalıcı olarak engellenmesine / kara listeye alınmasına**,
>    - İnternet Servis Sağlayıcınıza (İSS) veya hosting firmanıza **kötüye kullanım (abuse notice)** raporlanmasına,
>    - Türk Ceza Kanunu (TCK Madde 243-244) ve uluslararası bilişim suçları mevzuatları kapsamında **cezai ve hukuki yaptırımlarla karşılaşmanıza** yol açabilir.
> 5. **Geliştirici Sorumluluk Reddi:** Yazılım "olduğu gibi" (as-is) sunulmaktadır. Geliştirici, aracın üçüncü şahıslarca kötüye kullanımından, yetkisiz hedeflere yönlendirilmesinden veya doğabilecek hiçbir doğrudan/dolaylı hukuki ve maddi yaptırımdan sorumlu tutulamaz. **Tüm teknik, etik ve hukuki sorumluluk aracı çalıştıran kullanıcıya aittir.**

---

## 📊 Çalışma Modları Arasındaki Farklar

| Özellik / Kriter | 🟡 GitHub Pages Modu | 🟢 Yerel Sunucu Modu (`server.py`) |
| :--- | :--- | :--- |
| **Çalıştırma Ortamı** | Tarayıcı (`melihkarasu.github.io`) | Kendi bilgisayarınız (`127.0.0.1:8765`) |
| **Kurulum** | Yok, tek tıkla açılır | Tek komutla terminalden çalışır |
| **Temel Tarama: DoH DNS (DMARC, SPF, DNSSEC, CAA, IPv6)** | ✅ Tam ve Canlı | ✅ Tam ve Canlı |
| **Temel Tarama: HTTP Güvenlik Başlıkları** | ⚠️ Yarı-Otomatik (cURL yapıştırma) | ✅ %100 Otomatik |
| **Derin Pasif Tarama (Faz 1): Çerez analizi, TLS/sertifika, robots.txt ifşası, mixed content, teknoloji parmak izi** | ❌ | ✅ |
| **SAST Kaynak Kod Analizi (Faz 2): 42 kural, hardcoded secret'lar, SQLi/XSS/SSRF kalıpları, bağımlılık CVE (OSV)** | ❌ | ✅ |
| **Aktif Güvenlik Testi (Faz 3): SQL injection, XSS, CSRF, SSRF, IDOR, port taraması** | ❌ | ✅ (etik onay + rate limit ile) |
| **Çok Formatlı Rapor (Faz 4): Markdown + JSON + HTML, CVSS + CWE + doğrulama** | ⚠️ Sadece temel tarama raporu | ✅ Tüm sonuçlar dahil |
| **Localhost / İç Ağ Testi (`localhost:3000` vb.)** | ❌ | ✅ |
| **İstek Çıkış Noktası** | Kullanıcı tarayıcısı (DoH API'leri) | Kullanıcının kendi makine IP'si |

---

## 🚀 Hızlı Başlangıç

### Seçenek 1: Canlı Web Sürümü (Kurulumsuz)
Doğrudan tarayıcınızda açın:  
👉 **[https://melihkarasu.github.io/web-security-scanner/](https://melihkarasu.github.io/web-security-scanner/)**  
*(DoH DNS kayıtları tam taranır. Derin HTTP başlık denetimi için 2. sekmedeki "cURL Başlık Taraması" alanına `curl -I https://site.com` çıktısını yapıştırabilirsiniz).*

### Seçenek 2: Yerel Sunucu Modu (Tam Yetenek — Zahmetsiz)

Kendi bilgisayarınızda **sıfır bağımlılıkla** (yalnızca Python 3 ile) tek komutla çalıştırın:

#### ⚡ Linux & macOS:
```bash
git clone https://github.com/melihkarasu/web-security-scanner.git && cd web-security-scanner && python3 server.py
```

#### 🪟 Windows (PowerShell):
```powershell
git clone https://github.com/melihkarasu/web-security-scanner.git; cd web-security-scanner; python server.py
```

Sunucu başladığında tarayıcınız otomatik `http://127.0.0.1:8765` adresinde açılır ve arayüzde yeşil **"🟢 Lokal Mod"** rozeti görünür. Durdurmak için `Ctrl + C`.

---

## 🛡️ Yetenek Kataloğu

### 1️⃣ Temel Tarama (Her İki Mod)
- **HTTP Güvenlik Başlıkları:** CSP (unsafe-inline/eval analizi), HSTS (max-age + preload), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Bilgi İfşası:** `Server` ve `X-Powered-By` sızıntı tespiti ve puan cezası
- **DoH DNS & E-posta Savunması:** DMARC (p=reject/quarantine/none), SPF (-all/~all), DNSSEC (AD bayrağı), CAA, IPv6
- **Skorlama:** A+ → F notu, Nginx/Apache çözüm kodları

### 2️⃣ Derin Pasif Tarama — Faz 1 (Yalnızca Lokal)
- **Çerez Güvenliği:** Her `Set-Cookie` için HttpOnly / Secure / SameSite bayrak analizi
- **TLS / Sertifika:** Protokol versiyonu (TLS 1.0/1.1 tespiti), sertifika yetkilisi, kalan geçerlilik günü, SAN eşleşmesi
- **robots.txt İfşası:** /admin, /.env, /backup, /config gibi hassas dizin kalıpları
- **Mixed Content:** HTTP kaynaktan script/iframe (aktif) ve img/css (pasif) yükleme tespiti
- **Teknoloji Parmak İzi:** Server/X-Powered-By başlıkları, meta generator, WordPress/Next.js/Angular/React kalıpları, çerez adları

### 3️⃣ SAST — Kaynak Kod Analizi, Faz 2 (Yalnızca Lokal)
Proje dizininizi **42 kural, 10 kategori** ile tarar:
- **Sır Yönetimi (11 kural):** AWS/GitHub/GitLab/Slack/Google/OpenAI anahtarları, JWT secret'ları, kimlik içeren DB bağlantı string'leri, secret fallback kalıntıları (yanlış-pozitif filtresi ile)
- **SQL Injection (6 kural):** Template literal, string birleştirme, f-string, .format(), PHP içerpolasyonu, % formatlama
- **XSS Riski (5 kural):** innerHTML, document.write, dangerouslySetInnerHTML, v-html, insertAdjacentHTML
- **SSRF Riski (4 kural):** Kullanıcı girdisinden fetch/axios/urlopen/URL çağrıları
- **Path Traversal (2 kural):** Kullanıcı girdisinden open/readFile
- **Zayıf Kriptografi (2 kural):** MD5, SHA-1
- **Tehlikeli Fonksiyonlar (7 kural):** eval, exec, child_process, os.system, pickle.loads, güvenli olmayan yaml.load, kapalı TLS doğrulaması
- **Dockerfile / IaC (5 kural):** :latest imaj, USER root, COPY . ., Dockerfile içi secret, 0.0.0.0/0 erişim
- **Bağımlılık CVE Denetimi:** npm (lockfile destekli) / PyPI / Go modülleri — Google OSV veritabanı ile canlı sorgu

### 4️⃣ Aktif Güvenlik Testi — Faz 3 (Yalnızca Lokal, Etik Onay Gerekli)
Zorunlu etik beyan + rate limiting (1.5 sn/istek, maks. 60 istek) ile:
- **SQL Injection:** Error-based (DB motoru imzaları: MySQL/MSSQL/Oracle/PostgreSQL/SQLite), Boolean-based (AND 1=1 vs 1=2 + benzerlik analizi), Time-based (SLEEP)
- **XSS:** Reflected (zararsız benzersiz marker enjeksiyonu) + DOM-based sink tespiti
- **CSRF:** Form token kalıpları + SameSite çerez analizi
- **SSRF:** URL-benzeri parametrelere iç ağ adresi deneyip yanıt farkı analizi
- **IDOR:** Kimlik-benzeri parametre göstergeleri (danışma niteliğinde)
- **Port Taraması:** 24 yaygın TCP portu; riskli DB/altyapı portları vurgulanır
- **Derin Başlık Analizi:** CSP direktif detayları, CORS wildcard+credentials tehlikesi, Cache-Control eksikliği

### 5️⃣ Bulgu Yönetimi ve Raporlama — Faz 4
- **Kanıt Odaklı Bulgular:** Her bulgu; HTTP yanıtı / kod satırı kanıtı, şiddet, CWE sınıflandırması, CVSS yaklaşıklığı ve düzeltme önerisi içerir
- **Bağımsız Doğrulama:** İkinci geçişte her bulgu dosya yeniden okunarak teyit edilir (yanlış-pozitif azaltma — Cloudflare metodolojisi)
- **Kapsama Takibi:** Tetiklenen kural oranı, etkilenen dosyalar, doğrulama yüzdesi
- **Çok Formatlı Rapor:** Markdown (insan okunur), JSON (makine okunur / SIEM entegrasyonu), HTML (compliance-ready)

---

## 🔒 Güvenlik Mimarisi İlkeleri

- **Sadece Localhost Dinleme:** `server.py` yalnızca `127.0.0.1`'e bağlanır; açık proxy oluşturmaz.
- **Etik Onay Geçidi (Aktif Test):** Aktif istekler öncesi arayüzde zorunlu beyan + sunucuda domain bazlı onay kaydı; onaysız tarama `403 ETIK_ONAY_YOK` ile reddedilir.
- **Rate Limiting:** Aktif testlerde istekler arası 1.5 sn minimum bekleme, tarama başına 60 istek üst sınırı.
- **Yalnızca Okuma Amaçlı Payload'lar:** Aktif testler INSERT/UPDATE/DELETE göndermez; SQLi tespiti SELECT bağlamında zararsız prob'larla yapılır.
- **Sıfır Bağımlılık:** Yalnızca Python 3 standart kütüphanesi (`urllib`, `socket`, `ssl`, `http.server`) — arka kapı/supply-chain riski yok.
- **SAST Tarama Sınırları:** Dizin atlama listesi (node_modules, .git...), dosya boyutu limiti (1 MB), dosya sayısı limiti (800).

---

## 📁 Proje Yapısı

```text
web-security-scanner/
├── server.py                  # Yerel sunucu: statik dosyalar + API uçları
├── sast_engine.py             # Faz 2: SAST motoru (42 kural + OSV denetimi)
├── active_scan_engine.py      # Faz 3: Aktif test motoru (etik geçit + rate limit)
├── index.html                 # Arayüz (5 sekme: Denetim, cURL, SAST, Aktif, Kılavuz)
├── js/app.js                  # İstemci mantığı
├── css/mistral-theme.css      # Mistral AI tasarım katmanı
└── README.md
```

**API Uçları (yerel sunucu):**
- `GET /api/headers?url=` — HTTP başlık proxy'si
- `GET /api/deep-scan?url=` — Faz 1: derin pasif tarama
- `GET /api/sast?path=` — Faz 2: kaynak kod analizi
- `POST /api/active-confirm` — Faz 3: etik onay kaydı
- `GET /api/active-scan?url=&modules=` — Faz 3: aktif test (onay sonrası)

---

## 🏆 Krediler & Yetenek Kaynakları

Bu araç, aşağıdaki açık kaynak güvenlik projelerinin **yetenek alt kümelerini ve metodolojilerini** kendi motorlarında yeniden uygulayarak entegre eder:

- **[usestrix/strix](https://github.com/usestrix/strix)** → **Aktif test modülü (Faz 3):** SQL injection (error/boolean/time-based), XSS (reflected/DOM), CSRF, SSRF test yaklaşımları ve bulgu kanıtı üretimi Strix'in penetrasyon testi metodolojisinden uyarlanmıştır. *(Not: Strix'in çoklu AI ajan orkestrasyonu, Docker sandbox'ı ve LLM destekli otonom keşfi bu araçta yoktur; buradaki aktif testler deterministik ve rate-limited'tir.)*
- **[ersinkoc/security-check](https://github.com/ersinkoc/security-check)** → **SAST motoru (Faz 2):** Hardcoded secret tespiti, zayıf kriptografi, SQLi/XSS/SSRF kod kalıpları, Dockerfile/IaC denetimi ve OWASP odaklı kural tasarımı security-check'in kontrol listelerinden derlenmiştir. Ayrıca **derin pasif tarama (Faz 1)** kapsamındaki çerez/TLS/robots.txt/mixed-content kontrolleri bu kontrol listelerinden uyarlanmıştır.
- **[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)** → **Bulgu yönetimi (Faz 4):** Kanıt odaklı bulgu üretimi, bağımsız doğrulama geçişi ve kapsama takibi metodolojisi bu skill'in denetim yaklaşımından modellenmiştir.
- **Bağımlılık CVE verileri:** [Google OSV](https://osv.dev/) (açık kaynak zafiyet veritabanı).
- **[VibeCodedApps](https://app.melihkarasu.com):** Mikro uygulama portföyü ve üretim ortamı mimarisi.

---

## 📄 Lisans
Bu proje [MIT Lisansı](LICENSE) altında açık kaynak olarak yayınlanmıştır.
