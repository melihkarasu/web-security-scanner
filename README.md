# Web Security Scanner 🛡️

> **Pasif Güvenlik Başlıkları, DoH DNS & E-posta Savunma Taraması**  
> Hibrit Mimari: Canlı Demo (GitHub Pages) + Bağımsız Sıfır-Bağımlılık Yerel Sunucu (Local Mode)

[![GitHub Pages Demo](https://img.shields.io/badge/Canlı%20Demo-GitHub%20Pages-orange?style=flat-square)](https://melihkarasu.github.io/web-security-scanner/)
[![Local Mode](https://img.shields.io/badge/Local%20Mode-Python%203%20Stdlib-emerald?style=flat-square)](#-2-yerel-sunucu-modu-tam-ve-otomatik-tarama)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Design: Mistral AI](https://img.shields.io/badge/Design-Mistral%20AI-fa520f?style=flat-square)](https://mistral.ai)

---

## ⚖️ YASAL SORUMLULUK VE ETİK KULLANIM UYARISI

> **DİKKAT — KULLANICI SORUMLULUĞU:**  
> 1. Bu yazılım, **yalnızca sahibi olduğunuz, yönettiğiniz veya test etmek için açık yazılı izne sahip olduğunuz** sistemlerin pasif güvenlik duruşunu denetlemek amacıyla geliştirilmiştir.
> 2. **Yerel (Local) Modda Çalışırken:** Yazılım kullanıcının kendi yerel makinesinden (`127.0.0.1`) çalışır ve gönderilen tüm HTTP istekleri **kullanıcının kendi IP adresinden** çıkar.
> 3. İzniniz olmayan üçüncü parti web sitelerini, kamu kurumlarını, bankaları veya şirket altyapılarını hedef almak; otomatize veya sistematik döngülerle istek göndererek servisleri meşgul etmek (DDoS/Brute-force benzeri algılanma riski):
>    - Hedef sistemlerin **WAF (Web Application Firewall)** ve IDS/IPS mekanizmaları tarafından **IP adresinizin kalıcı olarak engellenmesine / kara listeye alınmasına**,
>    - İnternet Servis Sağlayıcınıza (İSS) veya hosting firmanıza **kötüye kullanım (abuse notice)** raporlanmasına,
>    - Türk Ceza Kanunu (TCK Madde 243-244) ve uluslararası bilişim suçları mevzuatları kapsamında **cezai ve hukuki yaptırımlarla karşılaşmanıza** yol açabilir.
> 4. **Geliştirici Sorumluluk Reddi:** Yazılım "olduğu gibi" (as-is) sunulmaktadır. Geliştirici, aracın üçüncü şahıslarca kötüye kullanımından, yetkisiz hedeflere yönlendirilmesinden veya doğabilecek hiçbir doğrudan/dolaylı hukuki ve maddi yaptırımdan sorumlu tutulamaz. **Tüm teknik, etik ve hukuki sorumluluk aracı çalıştıran kullanıcıya aittir.**

---

## 📊 İki Çalışma Modu Arasındaki Farklar

| Özellik / Kriter | 🟡 GitHub Pages Modu (Canlı Web) | 🟢 Yerel Sunucu Modu (`server.py`) |
| :--- | :--- | :--- |
| **Çalıştırma Ortamı** | Tarayıcı üzerinden doğrudan (`melihkarasu.github.io`) | Kendi bilgisayarınızda (`127.0.0.1:8765`) |
| **Kurulum / İndirme** | Kurulum yok, tek tıkla açılır | Tek komutla terminalden çalışır |
| **CORS Sınırı** | **Var:** Tarayıcı üçüncü parti sitelerin HTTP başlıklarını doğrudan okuyamaz | **Yok:** Yerel Python sunucusu doğrudan başlıkları çeker |
| **DoH DNS Taraması (DMARC, SPF, DNSSEC, CAA)** | ✅ Tam ve Canlı (Cloudflare & Google DoH) | ✅ Tam ve Canlı |
| **HTTP Güvenlik Başlıkları (CSP, HSTS, X-Frame)** | ⚠️ **Yarı-Otomatik:** 2. sekmeden cURL çıktısı yapıştırılır | 🚀 **%100 Otomatik:** Sadece URL girilir, başlıklar çekilir |
| **Localhost / İç Ağ Testi (`localhost:3000` vb.)** | ❌ Yapılamaz | ✅ Kendi yerel dev projelerinizi de test edebilirsiniz |
| **İstek Çıkış Noktası** | Kullanıcı tarayıcısı (DoH API'leri) | Kullanıcının kendi makine IP'si |

---

## 🚀 Hızlı Başlangıç

### Seçenek 1: Canlı Web Sürümü (Kurulumsuz)
Herhangi bir terminal veya indirme gerekmeden doğrudan tarayıcınızda açın:  
👉 **[https://melihkarasu.github.io/web-security-scanner/](https://melihkarasu.github.io/web-security-scanner/)**  
*(DoH DNS kayıtları tam taranır. Derin HTTP başlık denetimi için 2. sekmedeki "cURL Başlık Taraması" alanına `curl -I https://site.com` çıktısını yapıştırabilirsiniz).*

---

### Seçenek 2: Yerel Sunucu Modu (Tam Otomatik & Zahmetsiz)

Kendi bilgisayarınızda **sıfır bağımlılıkla** (ekstra `pip` veya `npm` paketi kurmadan, yalnızca sisteminizde kurulu Python 3 ile) tek bir komutla indirin ve çalıştırın:

#### ⚡ Tek Komutla Çalıştırma (Linux & macOS):
```bash
git clone https://github.com/melihkarasu/web-security-scanner.git && cd web-security-scanner && python3 server.py
```

#### 🪟 Windows (PowerShell):
```powershell
git clone https://github.com/melihkarasu/web-security-scanner.git; cd web-security-scanner; python server.py
```

*Sunucu başladığında tarayıcınız otomatik olarak `http://127.0.0.1:8765` adresinde açılır.*  
*Arayüz üstünde yeşil **"🟢 Lokal Mod"** rozeti görünür ve girdiğiniz sitenin tüm CSP, HSTS, X-Frame başlıkları anında canlı çekilir.*

Sunucuyu durdurmak için terminalde `Ctrl + C` tuşlarına basmanız yeterlidir.

---

## 🛡️ Neleri Denetler?

1. **HTTP Güvenlik Başlıkları:**
   - **Content-Security-Policy (CSP):** XSS ve enjeksiyon savunması; `unsafe-inline` ve `unsafe-eval` zayıflıkları.
   - **Strict-Transport-Security (HSTS):** SSL-stripping engeli, `max-age` süresi ve `preload` kontrolü.
   - **X-Frame-Options:** Clickjacking ve yetkisiz iframe gömme engeli (`DENY` / `SAMEORIGIN`).
   - **X-Content-Type-Options:** `nosniff` ile MIME sniffing engeli.
   - **Referrer-Policy:** URL sızıntı kısıtlamaları.
   - **Permissions-Policy:** Kamera, mikrofon ve konum donanım sınırlandırmaları.
   - **Bilgi İfşası Sızıntıları:** `Server` ve `X-Powered-By` ifşaları tespiti ve puan cezalandırması.
2. **DNS & E-posta Savunması (DoH):**
   - **DMARC:** `_dmarc.{domain}` e-posta sahteciliği koruması (`p=reject`, `p=quarantine`, `p=none`).
   - **SPF:** TXT kayıtlarından yetkili sunucu ve `-all` katılık analizi.
   - **DNSSEC:** Dijital imza ve DNS önbellek zehirlenmesi savunması (`AD=1`).
   - **CAA:** Yetkisiz CA'lerin SSL üretmesini engelleyen kayıt kontrolü.
   - **IPv6 Readiness:** AAAA kayıtları ile yeni nesil ağ protokolü kontrolü.
3. **Anında Düzeltme Kodları:**
   - Eksik her başlık için tek tıkla kopyalanabilen hazır **Nginx** ve **Apache** konfigürasyon kodları.
4. **Markdown Raporlama:**
   - Tek tıkla `.md` formatında kapsamlı denetim raporu indirme.

---

## 🔒 Güvenlik Mimarisi İlkeleri (server.py)

- **Sadece Localhost Dinleme:** `server.py` varsayılan olarak yalnızca `127.0.0.1` adresine bağlanır. Yerel ağınızdaki veya internetteki başka cihazlar sunucunuza erişemez; açık proxy oluşturulmaz.
- **Yalnızca Pasif HEAD/GET:** Sunucu hiçbir aktif fuzzing veya exploit payload'ı göndermez; sadece standart tarayıcı `HEAD` (reddedilirse `GET`) isteği atarak başlıkları toplar.
- **Zaman Aşımı ve Yönlendirme Sınırı:** Her istek için 8 saniye zaman aşımı uygulanır.

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
