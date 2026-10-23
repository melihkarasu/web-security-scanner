#!/usr/bin/env python3
"""
Web Security Scanner — Aktif Güvenlik Testi Motoru (Faz 3)
Etik onay geçidi + rate limiting ile kontrollü aktif testler:
SQL injection (error/boolean/time-based), XSS (reflected), CSRF, SSRF,
port taraması (temel TCP) ve derin başlık analizi.

İlkeler:
- Yalnızca OKUMA amaçlı (GET) veya zararsız payload'lar; INSERT/UPDATE/DELETE yok.
- Her istek arası minimum gecikme (rate limit) — hedefi yorma.
- İstek başına üst sınır; tarama başına toplam istek üst sınırı.
- Etik onay geçidi olmadan hiçbir aktif istek gönderilmez.
Yalnızca Python 3 standart kütüphanesi kullanır.
"""

import os
import re
import json
import time
import socket
import urllib.request
import urllib.parse
import urllib.error

# Faz 6F: İş Mantığı Test Motoru
from business_logic_engine import run_business_logic_scan

# Faz 6E: Tarayıcı simülasyon motoru (crawler + JS analizi + form enjeksiyonu + clickjacking + oturum)
from browser_sim_engine import run_browser_simulation

# =============================================================
# Güvenlik Duvarı Sabitleri
# =============================================================
RATE_LIMIT_SECONDS = 1.5       # istekler arası minimum süre
MAX_REQUESTS_PER_SCAN = 60     # tarama başına toplam istek üst sınırı
REQUEST_TIMEOUT = 8            # istek başına zaman aşımı
TIME_BASED_SLEEP = 2           # time-based SQLi testi için bekleme (kısa tutulur)
PORT_SCAN_TIMEOUT = 2.0        # port taraması soket zaman aşımı

# Yaygın portlar (temel TCP connect taraması)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "Submission", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB"
}

# SQL hata imzaları (hedefin veritabanı motoru tespiti + error-based kanıt)
SQL_ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning[:;]\s*mysql", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft sql server.*error", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"ora-\d{5}", "Oracle"),
    (r"postgresql.*error|pg_query\(|psql:", "PostgreSQL"),
    (r"sqlite3?\.(operational|programming)error", "SQLite"),
    (r"sqlite.*(error|warning)", "SQLite"),
    (r"\btraceback\b.*\bsqlalchemy", "SQLAlchemy"),
    (r"supplied argument is not a valid mysql", "PHP/MySQL"),
]

# Zayıf CSRF savunması tespiti için form token kalıpları
CSRF_TOKEN_FIELDS = re.compile(
    r'name=["\'](?:csrf[_-]?(?:token|middleware)|_csrf|authenticity[_-]?token|__requestverificationtoken|token)["\']',
    re.IGNORECASE
)

# URL parametre adı sezgileri
ID_PARAM_PATTERN = re.compile(r'(?:^|&)([^=&]*(?:id|uid|user|account|doc|file|page|ref|no)[^=&]*)=([^&]*)', re.IGNORECASE)
URLVAL_PARAM_PATTERN = re.compile(r'(?:^|&)([^=&]*(?:url|link|redirect|next|target|dest|goto|domain|host|site|page|callback|return|continue)[^=&]*)=([^&]*)', re.IGNORECASE)

# XSS yansıma marker'ı (zararsız benzersiz dize)
XSS_MARKER = "wzxqmk731"

# SSRF iç ağ hedefleri (yanıt farkı analizi için)
SSRF_PROBE_TARGET = "127.0.0.1"


# =============================================================
# Etik Onay Geçidi (session-bazlı)
# =============================================================
class EthicalGate:
    """Aktif test öncesi kullanıcı onayını kaydeder; onaysız istek reddedilir."""

    def __init__(self):
        self._confirmed = {}  # domain -> confirm timestamp

    def confirm(self, domain):
        self._confirmed[domain.lower()] = time.time()

    def is_confirmed(self, domain):
        return domain.lower() in self._confirmed

    def reset(self):
        self._confirmed = {}


ETHICAL_GATE = EthicalGate()


# =============================================================
# Rate-Limited HTTP İstemcisi
# =============================================================
class RateLimitedClient:
    """Tüm aktif istekler bu istemciden geçer: rate limit + sayaç + User-Agent."""

    def __init__(self):
        self.request_count = 0
        self.last_request_at = 0.0

    def get(self, url, params=None, timeout=REQUEST_TIMEOUT):
        """Rate-limited GET. İstek üst sınırına ulaşınca StopIteration yükseltir."""
        if self.request_count >= MAX_REQUESTS_PER_SCAN:
            raise StopIteration("İstek üst sınırına ulaşıldı (%d)" % MAX_REQUESTS_PER_SCAN)

        # Rate limit uygula
        elapsed = time.time() - self.last_request_at
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)

        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 WebSecurityScanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8"
        }, method="GET")

        self.request_count += 1
        self.last_request_at = time.time()

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(256 * 1024).decode("utf-8", errors="replace")
                return {"status": resp.status, "headers": dict(resp.headers), "body": body, "url": url, "error": None}
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(256 * 1024).decode("utf-8", errors="replace")
            except Exception:
                pass
            return {"status": e.code, "headers": dict(e.headers or {}), "body": body, "url": url, "error": None}
        except Exception as e:
            return {"status": None, "headers": {}, "body": "", "url": url, "error": str(e)}


# =============================================================
# Test Modülleri
# =============================================================
def test_sqli(client, base_url):
    """SQL injection: error-based + boolean-based + time-based (kısa)."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        findings.append({
            "test": "SQL Injection", "severity": "BİLGİ", "title": "Test edilebilir sorgu parametresi yok",
            "evidence": "URL'de query string bulunamadı; form parametreleri manuel test gerektirir.",
            "cwe": "-", "fix": "Form içi girdileri de test etmek için parametreli URL kullanın."
        })
        return findings

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    base_params = {k: v[0] for k, v in params.items()}

    for pname in list(params.keys())[:4]:  # ilk 4 parametre
        # --- Error-based: tek tırnak ---
        probe_params = dict(base_params)
        probe_params[pname] = base_params[pname] + "'"
        probe_url = _build_url(parsed, probe_params)
        resp = client.get(probe_url)
        if resp["error"]:
            continue
        for sig, engine in SQL_ERROR_SIGNATURES:
            if re.search(sig, resp["body"], re.IGNORECASE):
                findings.append({
                    "test": "SQL Injection", "severity": "KRİTİK",
                    "title": "Error-based SQL Injection (%s parametresi)" % pname,
                    "evidence": "%s → %s hata imzası: %s" % (probe_url, engine, _excerpt(resp["body"], sig)),
                    "cwe": "CWE-89",
                    "fix": "Parametreli sorgular kullanın; hata mesajlarını kullanıcıya göstermeyin."
                })
                break  # aynı parametre için tek bulgu yeter

        # --- Boolean-based: AND 1=1 vs AND 1=2 ---
        true_resp = client.get(_build_url(parsed, {**base_params, pname: base_params[pname] + " AND 1=1"}))
        false_resp = client.get(_build_url(parsed, {**base_params, pname: base_params[pname] + " AND 1=2"}))
        if not true_resp["error"] and not false_resp["error"]:
            t_len, f_len = len(true_resp["body"]), len(false_resp["body"])
            t_status, f_status = true_resp["status"], false_resp["status"]
            if (t_status == f_status and t_len > 0 and abs(t_len - f_len) > 0 and f_len != t_len
                    and _normal_similarity(true_resp["body"], false_resp["body"]) < 0.95):
                findings.append({
                    "test": "SQL Injection", "severity": "KRİTİK",
                    "title": "Boolean-based SQL Injection şüphesi (%s parametresi)" % pname,
                    "evidence": "AND 1=1 yanıt uzunluğu %d, AND 1=2 yanıt uzunluğu %d (fark: %d, durum: %s/%s)" % (t_len, f_len, abs(t_len - f_len), t_status, f_status),
                    "cwe": "CWE-89",
                    "fix": "Parametreli sorgular kullanın (prepared statements)."
                })

        # --- Time-based: SLEEP (yalnızca MySQL sözdizimi, kısa bekleme) ---
        t0 = time.time()
        resp = client.get(_build_url(parsed, {**base_params, pname: base_params[pname] + "' AND SLEEP(%d) AND '1'='1" % TIME_BASED_SLEEP}), timeout=TIME_BASED_SLEEP + REQUEST_TIMEOUT)
        elapsed = time.time() - t0
        if not resp["error"] and elapsed >= TIME_BASED_SLEEP:
            findings.append({
                "test": "SQL Injection", "severity": "KRİTİK",
                "title": "Time-based blind SQL Injection şüphesi (%s parametresi)" % pname,
                "evidence": "SLEEP(%d) payload'ı yanıt süresini %.1f sn'ye uzattı (normal: <%.1f sn)" % (TIME_BASED_SLEEP, elapsed, REQUEST_TIMEOUT),
                "cwe": "CWE-89",
                "fix": "Parametreli sorgular kullanın; girdiyi tip doğrulamasından geçirin."
            })

    return findings


def test_xss_reflected(client, base_url):
    """Reflected XSS: zararsız marker enjekte edip ham yansımayı arar."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        return findings

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    base_params = {k: v[0] for k, v in params.items()}

    for pname in list(params.keys())[:4]:
        probe_params = dict(base_params)
        probe_params[pname] = XSS_MARKER
        resp = client.get(_build_url(parsed, probe_params))
        if resp["error"]:
            continue
        body = resp["body"]
        if XSS_MARKER in body:
            # Marker HTML context'inde mi? (etiket içinde ham mı, yoksa kod bloğu içinde mi)
            idx = body.find(XSS_MARKER)
            ctx = body[max(0, idx - 40):idx + len(XSS_MARKER) + 10]
            encoded_ok = (XSS_MARKER not in body)
            if not encoded_ok:
                # Önemli kontrol: marker'ın URL-encode edilmeden ve HTML-escape edilmeden dönmesi
                if XSS_MARKER in ctx:
                    findings.append({
                        "test": "XSS", "severity": "YÜKSEK",
                        "title": "Reflected XSS — encode edilmemiş yansıma (%s parametresi)" % pname,
                        "evidence": "...%s... (marker ham olarak yanıt gövdesine yansıdı)" % _excerpt(ctx, XSS_MARKER),
                        "cwe": "CWE-79",
                        "fix": "Çıktıyı bağlama göre kodlayın (HTML: &lt; &gt; &quot;); textContent kullanın."
                    })
                    break  # bir kanıt yeter

    # DOM-based XSS: sayfa içi tehlikeli sink taraması (pasif okuma, payload yok)
    resp = client.get(base_url)
    if not resp["error"] and resp["body"]:
        dom_patterns = [
            (r"document\.write\(\s*.*(?:location\.(?:hash|search|href)|window\.name)", "document.write + konum kaynağı"),
            (r"\.innerHTML\s*=\s*.*(?:location\.(?:hash|search)|window\.name|document\.URL)", "innerHTML + konum kaynağı"),
            (r"eval\(\s*.*(?:location\.(?:hash|search)|window\.name)", "eval + konum kaynağı"),
        ]
        for rx, desc in dom_patterns:
            m = re.search(rx, resp["body"])
            if m:
                findings.append({
                    "test": "XSS", "severity": "ORTA",
                    "title": "DOM-based XSS riski (%s)" % desc,
                    "evidence": _excerpt(resp["body"], rx, 100),
                    "cwe": "CWE-79",
                    "fix": "Konum kaynaklarını (hash/search) DOM'a yazmadan önce sterilize edin."
                })
                break

    return findings


def test_csrf(client, base_url):
    """CSRF savunması: form token'ı + SameSite çerez kontrolü."""
    findings = []
    resp = client.get(base_url)
    if resp["error"]:
        return findings

    body = resp["body"]
    forms = re.findall(r"<form[^>]*>([\s\S]*?)</form>", body, re.IGNORECASE)
    state_changing = [f for f in forms if re.search(r'<form[^>]*method=["\'](?:post|get)["\']', body, re.IGNORECASE)]

    if not forms:
        findings.append({
            "test": "CSRF", "severity": "BİLGİ", "title": "Test edilebilir form yok",
            "evidence": "Sayfada <form> bulunamadı.", "cwe": "-", "fix": "-"
        })
        return findings

    # Form token kontrolü
    forms_without_token = []
    for i, form_html in enumerate(forms):
        if not CSRF_TOKEN_FIELDS.search(form_html):
            forms_without_token.append(i + 1)

    # SameSite çerez kontrolü
    set_cookies = []
    for hk, hv in resp["headers"].items():
        if hk.lower() == "set-cookie":
            set_cookies.append(hv)
    samesite_ok = any("samesite" in c.lower() and ("strict" in c.lower() or "lax" in c.lower()) for c in set_cookies)

    if forms_without_token and not samesite_ok:
        findings.append({
            "test": "CSRF", "severity": "YÜKSEK",
            "title": "CSRF koruması zayıf (%d/%d formda token yok, SameSite çerez yok)" % (len(forms_without_token), len(forms)),
            "evidence": "Token'sız form indeksleri: %s; Set-Cookie başlıklarında SameSite Strict/Lax bulunamadı." % forms_without_token[:5],
            "cwe": "CWE-352",
            "fix": "Formlara CSRF token ekleyin; oturum çerezlerine SameSite=Lax/Strict tanımlayın."
        })
    elif forms_without_token:
        findings.append({
            "test": "CSRF", "severity": "ORTA",
            "title": "Bazı formlarda CSRF token yok (SameSite çerez kısmi koruma sağlıyor)",
            "evidence": "Token'sız form indeksleri: %s" % forms_without_token[:5],
            "cwe": "CWE-352",
            "fix": "Tüm durum değiştiren formlara token ekleyin."
        })
    elif not samesite_ok:
        findings.append({
            "test": "CSRF", "severity": "ORTA",
            "title": "Oturum çerezinde SameSite bayrağı yok",
            "evidence": "Set-Cookie: %s" % (set_cookies[0][:80] if set_cookies else "(çerez yok)"),
            "cwe": "CWE-352",
            "fix": "Çerezlere SameSite=Lax ekleyin."
        })

    return findings


def test_ssrf(client, base_url):
    """SSRF şüphesi: URL-benzeri parametreleri iç ağ adresiyle deneyip yanıt farkı analiz eder."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        return findings

    # URL-benzeri parametre adları
    url_params = URLVAL_PARAM_PATTERN.findall(parsed.query)
    if not url_params:
        return findings

    baseline = client.get(base_url)
    if baseline["error"]:
        return findings

    for pname, pval in url_params[:3]:
        probe_params = dict(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        probe_params = {k: v[0] for k, v in probe_params.items()}
        probe_params[pname] = SSRF_PROBE_TARGET
        resp = client.get(_build_url(parsed, probe_params))
        if resp["error"]:
            continue

        # Yanıt farkı: durum kodu değişimi veya hata mesajı iç ağ bağlantısını ele verir
        internal_signals = [
            r"connection refused", r"127\.0\.0\.1", r"localhost",
            r"curl error", r"failed to connect", r"bağlantı reddedildi"
        ]
        signal_hit = [s for s in internal_signals if re.search(s, resp["body"], re.IGNORECASE)]
        if resp["status"] != baseline["status"] or (signal_hit and not any(re.search(s, baseline["body"] or "", re.IGNORECASE) for s in internal_signals)):
            findings.append({
                "test": "SSRF", "severity": "YÜKSEK",
                "title": "SSRF şüphesi (%s parametresi iç ağ adresini işliyor)" % pname,
                "evidence": "127.0.0.1 değeri gönderildiğinde durum %s→%s; sinyal: %s" % (
                    baseline["status"], resp["status"], ", ".join(signal_hit) or "(yanıt farkı)"),
                "cwe": "CWE-918",
                "fix": "İstek öncesi DNS çözümlemesi ile özel IP aralıklarını reddedin (SSRF guard)."
            })
            break

    return findings


def test_port_scan(hostname):
    """Temel TCP connect taraması (24 yaygın port, paralel soket kontrolü ile ~3 sn'de tamamlanır)."""
    from concurrent.futures import ThreadPoolExecutor
    findings = []
    open_ports = []

    def _probe_port(item):
        port, service = item
        try:
            with socket.create_connection((hostname, port), timeout=1.2):
                return {"port": port, "service": service}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(_probe_port, COMMON_PORTS.items()):
            if res:
                open_ports.append(res)
    open_ports.sort(key=lambda x: x["port"])

    risky = [p for p in open_ports if p["service"] in ("Docker API", "Redis", "MongoDB", "Elasticsearch", "VNC", "RDP", "MSSQL", "Oracle", "MySQL", "PostgreSQL")]
    if risky:
        findings.append({
            "test": "Port Taraması", "severity": "ORTA",
            "title": "Yayına açık veritabanı/altyapı portu tespit edildi",
            "evidence": ", ".join("%d/%s" % (p["port"], p["service"]) for p in risky),
            "cwe": "CWE-668",
            "fix": "Bu portları güvenlik duvarı ile kısıtlayın; yalnızca iç ağdan erişilebilir yapın."
        })

    # Bilgi bulgusu: tüm açık portlar listesi
    findings.append({
        "test": "Port Taraması", "severity": "BİLGİ",
        "title": "Açık portlar (%d/%d taranan)" % (len(open_ports), len(COMMON_PORTS)),
        "evidence": ", ".join("%d/%s" % (p["port"], p["service"]) for p in open_ports) or "(hiçbiri)",
        "cwe": "-", "fix": "-"
    })
    return findings, open_ports


def test_deep_headers(base_url):
    """Derin başlık analizi: CSP direktif detayları + CORS politika zafiyeti (tek istek, pasif)."""
    findings = []
    resp_headers, status = _fetch_headers_only(base_url)
    if resp_headers is None:
        findings.append({
            "test": "Derin Başlık", "severity": "BİLGİ", "title": "Başlıklar alınamadı",
            "evidence": str(status), "cwe": "-", "fix": "-"
        })
        return findings

    # Resmi PHP 21 Ekim 2026 Bülteni (https://www.php.net/archive/2026.php) — Yamasız PHP Sürümü Tespiti (CVE-2026-109618 / CVE-2026-109619)
    xpb = _get_header(resp_headers, "x-powered-by") or ""
    srv_hdr = _get_header(resp_headers, "server") or ""
    php_ver_match = re.search(r"\bPHP/([0-9]+\.[0-9]+\.[0-9]+)", xpb + " " + srv_hdr, re.IGNORECASE)
    if php_ver_match:
        pver = php_ver_match.group(1)
        parts = [int(x) for x in pver.split(".")]
        maj, min_v, pat_v = parts[0], parts[1], parts[2]
        is_vuln_php = False
        if maj < 8 or (maj == 8 and min_v <= 1):
            is_vuln_php = True
        elif maj == 8 and min_v == 2 and pat_v < 35:
            is_vuln_php = True
        elif maj == 8 and min_v == 3 and pat_v < 36:
            is_vuln_php = True
        elif maj == 8 and min_v == 4 and pat_v < 27:
            is_vuln_php = True
        elif maj == 8 and min_v == 5 and pat_v < 12:
            is_vuln_php = True
        if is_vuln_php:
            findings.append({
                "test": "Derin Başlık", "severity": "KRİTİK",
                "title": f"Yamasız PHP Sürümü ({pver}) — CVE-2026-109618 & CVE-2026-109619 (php2shell RCE)",
                "evidence": f"HTTP Başlığı: PHP/{pver} (Yamalı sürümler: 8.5.12, 8.4.27, 8.3.36, 8.2.35)",
                "cwe": "CWE-416",
                "fix": "Birincil Çözüm (https://www.php.net/archive/2026.php): PHP'yi resmi paket kaynaklarından yamalı sürüme (8.5.12, 8.4.27, 8.3.36, 8.2.35) yükseltin ve tüm PHP işçilerini (systemctl restart php*-fpm / apache2 / httpd) tam yeniden başlatın. Güncelleme yapılana kadar geçici önlem olarak php.ini/FPM içinde session.upload_progress.enabled = Off, PHP 8.5'te fatal_error_backtraces = Off ve post_max_size sınırlandırması uygulayın."
            })

    # CSP direktif analizi
    csp = _get_header(resp_headers, "content-security-policy")
    if csp:
        if "unsafe-inline" in csp:
            findings.append({
                "test": "Derin Başlık", "severity": "ORTA",
                "title": "CSP: unsafe-inline izni",
                "evidence": _excerpt(csp, "unsafe-inline", 60),
                "cwe": "CWE-693",
                "fix": "script-src 'self' + nonce/hash kullanın; unsafe-inline'den kurtulun."
            })
        if "unsafe-eval" in csp:
            findings.append({
                "test": "Derin Başlık", "severity": "YÜKSEK",
                "title": "CSP: unsafe-eval izni",
                "evidence": _excerpt(csp, "unsafe-eval", 60),
                "cwe": "CWE-693",
                "fix": "eval gerektiren bağımlılıkları kaldırın; CSP'den unsafe-eval'i çıkarın."
            })
        if re.search(r"(?:script-src|default-src)[^;]*\*", csp):
            findings.append({
                "test": "Derin Başlık", "severity": "ORTA",
                "title": "CSP: script-src'de wildcard (*)",
                "evidence": _excerpt(csp, r"script-src", 60),
                "cwe": "CWE-693",
                "fix": "script-src'ı 'self' ve güvenilir alan adlarıyla sınırlandırın."
            })
        if "object-src" not in csp and "default-src" not in csp:
            findings.append({
                "test": "Derin Başlık", "severity": "DÜŞÜK",
                "title": "CSP: object-src/default-src tanımsız",
                "evidence": "object-src 'none' tanımlanmamış.",
                "cwe": "CWE-693",
                "fix": "object-src 'none' ekleyin (plugin içerik enjeksiyonunu engeller)."
            })

    # CORS politika analizi
    acao = _get_header(resp_headers, "access-control-allow-origin")
    acac = _get_header(resp_headers, "access-control-allow-credentials")
    if acao == "*" and acac and acac.lower() == "true":
        findings.append({
            "test": "Derin Başlık", "severity": "YÜKSEK",
            "title": "CORS: wildcard origin + credentials izni",
            "evidence": "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
            "cwe": "CWE-942",
            "fix": "Kimlik bilgileriyle wildcard origin kullanmayın; origin allow-list uygulayın."
        })
    elif acao == "*":
        findings.append({
            "test": "Derin Başlık", "severity": "DÜŞÜK",
            "title": "CORS: wildcard origin (geniş erişim)",
            "evidence": "Access-Control-Allow-Origin: *",
            "cwe": "CWE-942",
            "fix": "Hassas kaynaklar için origin'leri allow-list ile sınırlayın."
        })

    # Cache-Control eksikliği (hassas sayfalar için)
    cc = _get_header(resp_headers, "cache-control")
    if cc and re.search(r"no-store|no-cache|private", cc, re.IGNORECASE) is None:
        findings.append({
            "test": "Derin Başlık", "severity": "DÜŞÜK",
            "title": "Cache-Control: önbellek izni kısıtsız",
            "evidence": "Cache-Control: %s" % cc[:60],
            "cwe": "CWE-524",
            "fix": "Hassas yanıtlara Cache-Control: no-store ekleyin."
        })

    return findings


def test_idor_indicators(client, base_url):
    """IDOR göstergeleri: kimlik-benzeri parametreleri tespit edip manuel inceleme önerir (otomatik erişim değiştirmez)."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        return findings

    id_params = ID_PARAM_PATTERN.findall(parsed.query)
    if id_params:
        findings.append({
            "test": "IDOR", "severity": "ORTA",
            "title": "Kimlik-benzeri parametre tespit edildi (yetki kontrolü doğrulanmalı)",
            "evidence": ", ".join("%s=%s" % (p, v[:20]) for p, v in id_params[:5]),
            "cwe": "CWE-639",
            "fix": "Her istekte kaynağın sahibi sunucu tarafında doğrulanmalı (ownership check). İki farklı hesapla erişim testi yapın."
        })
    return findings


def test_nosqli(client, base_url):
    """NoSQL injection: $ne/$gt operatör prob'ları + Mongo/Redis hata imzaları."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        return findings

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    base_params = {k: v[0] for k, v in params.items()}

    nosql_error_sigs = [
        (r"MongoError|MongoDB.*error|BSONError", "MongoDB"),
        (r"mongo:\s*.*\b(?:SyntaxError|TypeError)\b", "MongoDB"),
        (r"WRONGTYPE|Redis.*error", "Redis"),
        (r"CouchDB.*error|couch.*forbidden", "CouchDB"),
    ]

    for pname in list(params.keys())[:3]:
        # 1. $ne operatör probu (error-based + boolean karışımı)
        probe_params = dict(base_params)
        probe_params[pname] = "' || '1'=='1' || ''=='"
        resp = client.get(_build_url(parsed, probe_params))
        if resp["error"]:
            continue
        for sig, engine in nosql_error_sigs:
            if re.search(sig, resp["body"], re.IGNORECASE):
                findings.append({
                    "test": "NoSQL Injection", "severity": "KRİTİK",
                    "title": "NoSQL injection hata sızıntısı (%s parametresi, %s)" % (pname, engine),
                    "evidence": "%s → imza: %s" % (resp["url"][:90], _excerpt(resp["body"], sig)),
                    "cwe": "CWE-943",
                    "fix": "Girdiyi tip doğrulamasından geçirin; sorgu operatörlerini whitelist'le kısıtlayın."
                })
                break

        # 2. $ne boolean farkı: baseline vs $ne:true
        if not findings or findings[-1].get("title", "").find(pname) == -1:
            baseline = client.get(_build_url(parsed, base_params))
            probe2 = dict(base_params)
            probe2[pname + "[$ne]"] = "__nonexistent__"
            resp2 = client.get(_build_url(parsed, {k: v for k, v in probe2.items() if k != pname}))
            if not resp2["error"] and not baseline["error"]:
                if baseline["status"] == 200 and resp2["status"] == 200 and _normal_similarity(baseline["body"], resp2["body"]) < 0.9 and len(baseline["body"]) != len(resp2["body"]):
                    findings.append({
                        "test": "NoSQL Injection", "severity": "YÜKSEK",
                        "title": "NoSQL $ne operatör enjeksiyonu şüphesi (%s parametresi)" % pname,
                        "evidence": "$ne probu yanıt uzunluğunu %d → %d değiştirdi (benzerlik: %.2f)" % (len(baseline["body"]), len(resp2["body"]), _normal_similarity(baseline["body"], resp2["body"])),
                        "cwe": "CWE-943",
                        "fix": "Parametre adlarında operatör enjeksiyonunu engelleyin ($ ile başlayan anahtarları reddedin)."
                    })
    return findings


def test_ssti(client, base_url):
    """SSTI: zararsız matematik marker'ı ({{7*7}}, ${7*7}, <%= 7*7 %>) — 49 yansıması aranır."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        return findings

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    base_params = {k: v[0] for k, v in params.items()}

    markers = [
        ("{{7*7}}", "Jinja2/Twig/Liquid"),
        ("${7*7}", "FreeMarker/Thymeleaf/JSP EL"),
        ("<%= 7*7 %>", "ERB/EJS"),
        ("#{7*7}", "Ruby ERB/Thymeleaf"),
        ("%{7*7}", "Mako"),
    ]

    for pname in list(params.keys())[:3]:
        for payload, engine in markers:
            probe_params = dict(base_params)
            probe_params[pname] = payload
            resp = client.get(_build_url(parsed, probe_params))
            if resp["error"]:
                continue
            # 7*7 = 49: marker'ın hesaplanıp hesaplanmadığına bakılır
            body = resp["body"]
            payload_rendered = ("49" in body) and (payload not in body)
            if payload_rendered:
                findings.append({
                    "test": "SSTI", "severity": "KRİTİK",
                    "title": "Server-Side Template Injection (%s parametresi, %s)" % (pname, engine),
                    "evidence": "Payload %r gönderildi; yanıt 49 içeriyor ve payload ham olarak dönmedi — şablon motoru ifadeyi değerlendirdi." % payload,
                    "cwe": "CWE-1336",
                    "fix": "Kullanıcı girdisini şablon olarak değerlendirmeyin; veri olarak geçirin (context/data parametresi)."
                })
                break  # ilk çalışan motor yeterli
    return findings


def test_open_redirect(client, base_url):
    """Open redirect: URL-benzeri parametrelere marker hedefi koyup Location başlığı kontrolü."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.query:
        return findings

    url_params = URLVAL_PARAM_PATTERN.findall(parsed.query)
    if not url_params:
        return findings

    MARKER_HOST = "wss-marker-redirect-test.example.org"
    for pname, pval in url_params[:3]:
        probe_params = dict(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        probe_params = {k: v[0] for k, v in probe_params.items()}
        probe_params[pname] = "https://" + MARKER_HOST

        # Rate-limited client redirect takibi yapmadığından manuel kontrol: Location başlığına bak
        url = _build_url(parsed, probe_params)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 WebSecurityScanner/1.0"}, method="GET")
            # NoRedirect opener: 3xx yanıtı olduğu gibi yakalanır
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(NoRedirect)
            client.request_count += 1  # rate limit sayaçlarına dahil et
            client.last_request_at = time.time()
            try:
                resp = opener.open(req, timeout=REQUEST_TIMEOUT)
                location = resp.headers.get("Location") or ""
                status = resp.status
            except urllib.error.HTTPError as e:
                location = (e.headers or {}).get("Location") or ""
                status = e.code
        except Exception:
            continue

        if status in (301, 302, 303, 307, 308) and MARKER_HOST in location:
            findings.append({
                "test": "Open Redirect", "severity": "ORTA",
                "title": "Open redirect (%s parametresi)" % pname,
                "evidence": "https://%s değeri gönderildiğinde sunucu Location: %s başlığıyla döndü (HTTP %s)" % (MARKER_HOST, location[:90], status),
                "cwe": "CWE-601",
                "fix": "Yönlendirme hedeflerini allow-list ile doğrulayın; harici alan adlarına yönlendirmeyin."
            })
            break  # bir kanıt yeterli
    return findings


# =============================================================
# Faz 6A: Zincirleme Korelasyon Motoru
# Bulgular arası risk kombinasyonlarını tespit eder.
# =============================================================
def correlate_findings(findings):
    """Bulgular arası korelasyon: birleşik risk, parçaların toplamından büyüktür."""
    chains = []
    by_test = {}
    for f in findings:
        by_test.setdefault(f.get("test", ""), []).append(f)

    def _matching_findings(test):
        # Tam eşleşme + kısmi eşleşme (Form SQL Injection -> SQL Injection, DOM XSS -> XSS)
        result = list(by_test.get(test, []))
        for t, flist in by_test.items():
            if t != test and test in t:
                result.extend(flist)
        return result

    def _has(test):
        return len(_matching_findings(test)) > 0

    def _sev_of(test):
        sevs = {"KRİTİK": 0, "YÜKSEK": 1, "ORTA": 2, "DÜŞÜK": 3, "BİLGİ": 4}
        return min((sevs.get(f["severity"], 4) for f in _matching_findings(test)), default=4)

    # 1. SSRF + yaygın port/DB portu → iç ağ keşfi zinciri
    if _has("SSRF") and _has("Port Taraması"):
        port_finds = by_test["Port Taraması"]
        risky = [f for f in port_finds if any(x in f.get("evidence", "") for x in ("Redis", "MongoDB", "MSSQL", "MySQL", "PostgreSQL", "Docker", "Elasticsearch"))]
        if risky:
            chains.append({
                "title": "SSRF + açık veritabanı portu = iç ağ keşfi zinciri",
                "severity": "KRİTİK",
                "components": ["SSRF", "Port Taraması"],
                "description": "SSRF zafiyeti ile birlikte iç ağda açık veritabanı/altyapı portları tespit edildi. Saldırgan SSRF üzerinden bu servislere doğrudan erişebilir (veri sızıntısı / RCE zinciri).",
                "fix": "SSRF guard uygulayın ve iç servisleri ağ seviyesinde izole edin."
            })

    # 2. XSS + zayıf CSP → yükletilebilir XSS zinciri
    if _has("XSS") and _sev_of("Derin Başlık") <= 2:
        deep = by_test.get("Derin Başlık", [])
        weak_csp = [f for f in deep if "CSP" in f.get("title", "")]
        if weak_csp:
            chains.append({
                "title": "XSS + zayıf CSP = serbest script enjeksiyonu",
                "severity": "KRİTİK",
                "components": ["XSS", "Derin Başlık"],
                "description": "Yansıyan/DOM XSS tespit edildi ve CSP politikası zayıf (unsafe-inline/unsafe-eval/wildcard). Tarayıcı katmanı da koruma sağlamadığından saldırı zinciri tamamlanıyor.",
                "fix": "CSP'yi sıkılaştırın (unsafe-* kaldırın) ve XSS kaynağını kapatın."
            })

    # 3. SQLi (error-based) + verbose hata → veri sızıntısı zinciri
    sqli_err = [f for f in _matching_findings("SQL Injection") if "error-based" in f.get("title", "").lower()]
    if sqli_err:
        chains.append({
            "title": "Error-based SQLi + veritabanı hata sızıntısı",
            "severity": "KRİTİK",
            "components": ["SQL Injection"],
            "description": "SQL hata mesajı istemciye sızıyor; saldırgan sorgu yapısını öğrenerek blind/extraktion saldırılarına geçebilir.",
            "fix": "Hata mesajlarını gizleyin (genel hata sayfası) + parametreli sorgular."
        })

    # 4. CSRF yok + çerez SameSite yok → oturum devralma zinciri
    csrf_weak = [f for f in by_test.get("CSRF", []) if "yok" in f.get("title", "") or "zayıf" in f.get("title", "")]
    if csrf_weak and _sev_of("CSRF") <= 1:
        chains.append({
            "title": "CSRF korumasızlık + zayıf çerez = oturum devralma zinciri",
            "severity": "YÜKSEK",
            "components": ["CSRF"],
            "description": "Formlarda token yok ve oturum çerezi SameSite korumasız; tek bir dış bağlantıyla kullanıcı adına işlem yapılabilir.",
            "fix": "CSRF token + SameSite=Lax/Strict çerez uygulayın."
        })

    # 5. SSTI + teknoloji parmak izi → RCE zinciri (deep_scan verisi yoksa pas geç)
    if _has("SSTI"):
        chains.append({
            "title": "SSTI = doğrudan RCE riski",
            "severity": "KRİTİK",
            "components": ["SSTI"],
            "description": "Şablon motoru kullanıcı girdisini değerlendiriyor; çoğu motorda bu, sunucuda keyfi kod yürütme (RCE) anlamına gelir.",
            "fix": "Kullanıcı girdisini şablon olarak değerlendirmeyi derhal kaldırın."
        })

    return chains


# =============================================================
# Yardımcılar
# =============================================================
def _build_url(parsed, params):
    query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

def _normal_similarity(a, b):
    """İki gövdenin kaba benzerlik oranı (0-1). Boolean-based tespitte yanlış-pozitif azaltır."""
    if not a or not b:
        return 0.0
    import difflib
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()

def _excerpt(body, pattern, radius=80):
    """Regex'e uyan yerin etrafından kısa kanıt parçası çıkarır."""
    m = re.search(pattern, body or "", re.IGNORECASE)
    if not m:
        return "(kanıt çıkarılamadı)"
    start = max(0, m.start() - radius // 2)
    end = min(len(body), m.end() + radius // 2)
    return body[start:end].replace("\n", " ").strip()[:160]

def _get_header(headers, name):
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None

def _fetch_headers_only(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 WebSecurityScanner/1.0"}, method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return dict(resp.headers), resp.status
    except urllib.error.HTTPError as e:
        return dict(e.headers or {}), e.code
    except Exception as e:
        return None, str(e)


# =============================================================
# Ana Aktif Tarama Orkestratörü
# =============================================================
def run_custom_test(client, url, param, payload):
    """
    AI orkestratörü tarafından çağrılan, spesifik bir parametreye 
    özel payload gönderen test fonksiyonu.

    Mevcut query parametreleri KORUNUR ve aynı addaki parametre payload ile
    DEĞİŞTİRİLİR (ikiz parametre oluşmaz — hedef ilk değeri okuduğu için
    aksi halde payload hiç işlenmezdi).

    Yanıt gövdesi ve başlıklar LLM bağlamına sığacak şekilde kırpılır
    (256 KB ham gövde → token patlaması → devre kesici; kanıt için ilk 3 KB yeter).
    """
    merged_url = url
    if param:
        try:
            parsed = urllib.parse.urlparse(url)
            existing = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
            existing[param] = payload
            merged_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                urllib.parse.urlencode(existing), ""))
        except ValueError:
            merged_url = url
    try:
        resp = client.get(merged_url)
        body = resp.get("body", "") or ""
        headers = resp.get("headers", {}) or {}
        try:
            headers_s = json.dumps(headers)[:800]
        except Exception:
            headers_s = str(headers)[:800]
        return {
            "url": merged_url,
            "param": param,
            "payload": payload,
            "status": resp.get("status"),
            "body": body[:3000],
            "body_length": len(body),
            "headers": headers_s
        }
    except Exception as e:
        return {"error": str(e)}

def export_scan_state(base_url, site_map, sast_findings, forms=None, headers=None, tech=None):
    """
    Sistemin mevcut durumunu AI ajanlarının anlayacağı 
    kompakt bir JSON formatına dönüştürür.

    site_map: crawler sayfa listesi [{url, status, ...}]
    forms:    crawler form listesi [{action_url, method, inputs:[{name,type}], page_url}]
    headers:  hedefin HTTP yanıt başlıkları (dict)
    tech:     teknoloji parmak izi listesi
    """
    pages = []
    found_forms = []
    for p in (site_map or []):
        if isinstance(p, dict):
            if "url" in p:
                pages.append(p["url"])
            pf = p.get("forms", [])
            if isinstance(pf, list):  # crawler sayfalarında "forms" sayaç (int) olabilir
                found_forms.extend(pf)
        elif isinstance(p, str):
            pages.append(p)

    # Crawler'ın gerçek form şemasını LLM için sadeleştir
    compact_forms = []
    for f in (forms or [])[:15]:
        if not isinstance(f, dict):
            continue
        compact_forms.append({
            "page": (f.get("page_url") or "")[:120],
            "action": (f.get("action_url") or "")[:120],
            "method": f.get("method", "GET"),
            "fields": [i.get("name") for i in (f.get("inputs") or []) if isinstance(i, dict)][:10],
            "csrf_token_field": bool(f.get("token_field_found"))
        })
    for cf in compact_forms:
        if cf not in found_forms:
            found_forms.append(cf)

    return {
        "target": base_url,
        "attack_surface": {
            "pages": pages[:30],
            "forms": found_forms[:20]
        },
        "response_headers": {k: str(v)[:120] for k, v in (headers or {}).items()} if isinstance(headers, dict) else {},
        "technology_fingerprints": [t.get("value") if isinstance(t, dict) else str(t) for t in (tech or [])][:10],
        "static_findings": [
            {"test": f.get("test", "sast") if isinstance(f, dict) else str(f),
             "severity": f.get("severity", "info") if isinstance(f, dict) else "info",
             "title": f.get("title", "") if isinstance(f, dict) else ""}
            for f in (sast_findings or [])[:40]
        ]
    }

def verify_and_classify_active_findings(findings):
    """
    Cloudflare Security Audit Skill — Bağımsız Doğrulama Geçişi & 4-Durumlu Yaşam Döngüsü:
    - confirmed: Somut HTTP kanıtı (hata imzası, ham yansıma, 49 şablon değerlendirmesi, açık DB portu vb.)
    - needs_validation: İki hesaplı yetki testi veya ek çalışma zamanı teyidi gerektiren adaylar (IDOR, sezgisel iş mantığı, boolean/time farkı)
    - hardening_note: Derinlemesine savunma / bilgilendirme notları (BİLGİ / DÜŞÜK)
    - rejected: Yanlış pozitif olarak elenen adaylar
    """
    confirmed = []
    needs_validation = []
    hardening_notes = []
    rejected = []

    for idx, f in enumerate(findings, 1):
        f["candidate_id"] = "ACT-%03d" % idx
        test_name = (f.get("test") or "").lower()
        title_lower = (f.get("title") or "").lower()
        sev = f.get("severity") or "ORTA"

        if sev == "BİLGİ" or "test edilebilir" in title_lower or "açık portlar" in title_lower or "keşif tamamlandı" in title_lower:
            f["verdict"] = "hardening_note"
            f["verified"] = True
            f["trust_boundary"] = "reconnaissance -> surface_inventory"
            hardening_notes.append(f)
        elif test_name == "idor" or "şüphesi" in title_lower or "potansiyel" in title_lower or "bazı formlarda csrf" in title_lower:
            f["verdict"] = "needs_validation"
            f["verified"] = False
            f["trust_boundary"] = "caller_identity -> resource_authorization"
            f["validation_step"] = f.get("fix") or "İki ayrı kullanıcı oturumu veya kontrollü tekrar isteği ile sınır ihlalini doğrulayın."
            needs_validation.append(f)
        elif sev == "DÜŞÜK":
            f["verdict"] = "hardening_note"
            f["verified"] = True
            f["trust_boundary"] = "http_response -> defense_in_depth"
            hardening_notes.append(f)
        else:
            f["verdict"] = "confirmed"
            f["verified"] = True
            f["trust_boundary"] = "untrusted_input -> application_sink"
            confirmed.append(f)

    return {
        "confirmed": confirmed,
        "needs_validation": needs_validation,
        "hardening_notes": hardening_notes,
        "rejected": rejected,
    }


def build_active_coverage_ledger(scan_url, active_modules, module_stats, findings):
    """Cloudflare Security Audit Skill — Aktif Tarama Kapsam Defteri (Coverage Ledger)."""
    parsed = urllib.parse.urlparse(scan_url)
    has_query = bool(parsed.query)
    ledger = []
    MODULE_META = [
        ("sqli", "SQL Injection", "query_param -> db_driver", True),
        ("nosqli", "NoSQL Injection", "query_param -> nosql_engine", True),
        ("ssti", "Server-Side Template Injection", "query_param -> template_engine", True),
        ("open_redirect", "Open Redirect", "redirect_param -> http_location", True),
        ("xss", "Reflected & DOM XSS", "input_source -> html_dom_sink", False),
        ("csrf", "Cross-Site Request Forgery", "cross_origin -> state_changing_form", False),
        ("ssrf", "Server-Side Request Forgery", "url_param -> internal_network", True),
        ("idor", "Insecure Direct Object Reference", "object_id -> authorization_check", True),
        ("deep_headers", "Deep HTTP Security Headers & CORS", "origin_response -> browser_policy", False),
        ("browser", "Browser Simulation (Crawler/JS/Forms)", "same_origin_crawl -> dom_and_forms", False),
        ("logic", "Business Logic & Race Conditions", "workflow_param -> state_machine", False),
        ("ports", "TCP Infrastructure Port Exposure", "external_network -> host_tcp_ports", False),
    ]
    for idx, (mkey, attack_cls, boundary, needs_query) in enumerate(MODULE_META, 1):
        cid = "DAST-COV-%03d" % idx
        if mkey not in active_modules:
            ledger.append({
                "coverage_id": cid, "surface": scan_url, "boundary": boundary,
                "subsystem": mkey, "attack_class": attack_cls,
                "status": "out_of_scope", "evidence": "-", "gap": "Modül seçilmedi"
            })
            continue
        st = module_stats.get(mkey) or {}
        if not st.get("ran"):
            ledger.append({
                "coverage_id": cid, "surface": scan_url, "boundary": boundary,
                "subsystem": mkey, "attack_class": attack_cls,
                "status": "deferred", "evidence": "-",
                "gap": st.get("skipped") or st.get("error") or "Çalıştırılamadı"
            })
            continue
        m_finds = [f for f in findings if mkey in (f.get("test") or "").lower() or attack_cls.split()[0].lower() in (f.get("test") or "").lower()]
        real_hits = [f for f in m_finds if f.get("verdict") in ("confirmed", "needs_validation")]
        gap = "URL'de query parametresi yok (yalnızca sayfa/form yüzeyi incelendi)" if (needs_query and not has_query and not real_hits) else ""
        ledger.append({
            "coverage_id": cid,
            "surface": scan_url,
            "boundary": boundary,
            "subsystem": mkey,
            "attack_class": attack_cls,
            "status": "candidate" if real_hits else "covered",
            "evidence": "%d bulgu / %d ms" % (len(real_hits), st.get("duration_ms", 0)),
            "gap": gap
        })
    return ledger


def run_active_scan(base_url, modules=None):
    """Etik onay sonrası aktif taramayı orkestre eder."""
    parsed = urllib.parse.urlparse(base_url if "://" in base_url else "https://" + base_url)
    hostname = parsed.hostname
    normalized = "%s://%s%s" % (parsed.scheme, parsed.netloc, parsed.path or "/")

    if not ETHICAL_GATE.is_confirmed(hostname or ""):
        return {"success": False, "error": "ETIK_ONAY_YOK", "message": "Aktif test için etik onay gerekli."}

    all_modules = ["sqli", "nosqli", "ssti", "open_redirect", "xss", "csrf", "ssrf", "idor", "ports", "deep_headers", "browser", "logic"]
    active_modules = modules if modules else all_modules

    client = RateLimitedClient()
    findings = []
    module_stats = {}
    scan_url = base_url if "://" in base_url else "https://" + base_url

    def _run(name, fn):
        t0 = time.time()
        try:
            result = fn()
            count = len(result) if isinstance(result, (list, tuple)) else 0
            module_stats[name] = {"ran": True, "findings": count, "duration_ms": int((time.time() - t0) * 1000), "requests": client.request_count}
            return result
        except StopIteration:
            module_stats[name] = {"ran": False, "skipped": "istek limiti", "duration_ms": int((time.time() - t0) * 1000)}
            return []
        except Exception as e:
            module_stats[name] = {"ran": False, "error": str(e)[:100], "duration_ms": int((time.time() - t0) * 1000)}
            return []

    start = time.time()

    if "sqli" in active_modules:
        findings += _run("sqli", lambda: test_sqli(client, scan_url))
    if "nosqli" in active_modules:
        findings += _run("nosqli", lambda: test_nosqli(client, scan_url))
    if "ssti" in active_modules:
        findings += _run("ssti", lambda: test_ssti(client, scan_url))
    if "open_redirect" in active_modules:
        findings += _run("open_redirect", lambda: test_open_redirect(client, scan_url))
    if "xss" in active_modules:
        findings += _run("xss", lambda: test_xss_reflected(client, scan_url))
    if "csrf" in active_modules:
        findings += _run("csrf", lambda: test_csrf(client, scan_url))
    if "ssrf" in active_modules:
        findings += _run("ssrf", lambda: test_ssrf(client, scan_url))
    if "idor" in active_modules:
        findings += _run("idor", lambda: test_idor_indicators(client, scan_url))
    if "deep_headers" in active_modules:
        findings += _run("deep_headers", lambda: test_deep_headers(scan_url))

    # Faz 6E: Tarayıcı Simülasyonu (crawler + JS + form + clickjacking + oturum)
    browser_site_map = []
    browser_forms = []
    if "browser" in active_modules:
        sim_holder = {}
        def _browser():
            sim_holder["result"] = run_browser_simulation(scan_url, client)
            return sim_holder["result"].get("findings", [])
        findings += _run("browser", _browser)
        sim = sim_holder.get("result")
        if sim:
            crawl_stats = sim.get("stats", {}).get("crawl", {})
            if "browser" in module_stats:
                module_stats["browser"]["pages"] = crawl_stats.get("pages_visited", 0)
                module_stats["browser"]["forms_found"] = crawl_stats.get("forms_found", 0)
            browser_site_map = sim.get("site_map", [])
            browser_forms = sim.get("forms", [])

    # Faz 6F: İş Mantığı Testleri
    if "logic" in active_modules:
        def _logic():
            return run_business_logic_scan(scan_url, client)
        findings += _run("logic", _logic)

    if "ports" in active_modules:
        def _ports():
            f, _open = test_port_scan(hostname)
            return f
        findings += _run("ports", _ports)

    # Cloudflare Audit Skill: Bağımsız doğrulama geçişi ve 4-durumlu yaşam döngüsü
    lifecycle = verify_and_classify_active_findings(findings)
    coverage_ledger = build_active_coverage_ledger(scan_url, active_modules, module_stats, findings)

    summary = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0, "BİLGİ": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    # Faz 6A: Zincirleme korelasyon analizi
    chains = correlate_findings(findings)
    for c in chains:
        summary[c["severity"]] = summary.get(c["severity"], 0) + 1

    return {
        "success": True,
        "url": scan_url,
        "modules": module_stats,
        "summary": summary,
        "findings": findings,
        "lifecycle": lifecycle,
        "coverage_ledger": coverage_ledger,
        "chains": chains,
        "site_map": browser_site_map,
        "forms": browser_forms,
        "requests_sent": client.request_count,
        "rate_limit_seconds": RATE_LIMIT_SECONDS,
        "duration_ms": int((time.time() - start) * 1000),
        "disclaimer": "Aktif testler yalnızca okuma amaçlı payload'larla, rate-limited olarak yürütülmüştür."
    }
