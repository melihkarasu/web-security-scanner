#!/usr/bin/env python3
"""
Web Security Scanner — Bağımsız Lokal Sunucu (Zero-Dependency)
Yalnızca Python 3 standart kütüphanesini kullanır (ekstra pip paketi gerektirmez).

Görevleri:
1. Statik web arayüzünü (index.html, css, js) yerel olarak servis eder.
2. /api/headers uç noktası üzerinden hedef sitenin gerçek HTTP yanıt başlıklarını çeker (CORS engelini aşar).
3. Yalnızca 127.0.0.1 üzerinde dinler; dış ağlara veya internete açık proxy oluşturmaz.
"""

import sys
import os
import json
import re
import ssl
import socket
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, ThreadingHTTPServer, SimpleHTTPRequestHandler
import webbrowser
import threading
import time
import secrets
import hmac

# Faz 3: Aktif tarama motoru (etik onay geçidi + rate limiter içerir)
from active_scan_engine import ETHICAL_GATE, run_active_scan, run_custom_test, export_scan_state, RateLimitedClient, RATE_LIMIT_SECONDS
from ai_orchestrator import AIOrchestrator
from ai_connector import AIProviderFactory
from redaction import redact_text
from ai_jobs import AIJobManager, JobLimitError
import scan_history
import security_assistant
import threat_intel
import headless_browser
import updater
from strix_engine import STRIX_MANAGER, strix_capabilities

HOST = os.environ.get("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("PORT", "8765"))
NO_BROWSER = os.environ.get("NO_BROWSER", "0").lower() in ("1", "true", "yes")
EDITION = "lite" if ("--lite" in sys.argv or os.environ.get("WSS_EDITION", "").lower() == "lite") else "full"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 WebSecurityScanner/1.0"
TIMEOUT_SECONDS = 8
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Yerel API güvenliği (PentAGI'nin Bearer token yaklaşımının yerel uyarlaması) ---
# Oturum anahtarı her açılışta rastgele üretilir; CLI/CI için WSS_API_TOKEN ile sabitlenebilir.
API_TOKEN_FROM_ENV = bool(os.environ.get("WSS_API_TOKEN", "").strip())
API_TOKEN = os.environ.get("WSS_API_TOKEN", "").strip() or secrets.token_urlsafe(32)
# DNS rebinding koruması: yalnızca bu ana makine adlarıyla gelen isteklere yanıt verilir.
ALLOWED_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"} | {
    h.strip().lower() for h in os.environ.get("WSS_ALLOWED_HOSTS", "").split(",") if h.strip()})
# Tarama başlatan uçlar yalnızca POST ile çağrılabilir.
POST_ONLY_API_PATHS = frozenset({"/api/active-scan", "/api/ai-scan"})
# Statik servis izin listesi: kaynak kod, .git, rapor ve test dizinleri servis edilmez.
STATIC_ALLOWED_PREFIXES = ("/css/", "/js/", "/assets/", "/img/", "/images/", "/fonts/", "/icons/")
STATIC_ALLOWED_ROOT_EXT = (".html", ".ico", ".png", ".svg", ".jpg", ".jpeg", ".webp", ".gif", ".webmanifest")
TOKEN_META_PLACEHOLDER = '<meta name="wss-token" content="">'
AI_JOBS = AIJobManager()  # Faz 2: arka plan AI işleri (yalnız bellek)
# Faz 3: tehdit istihbaratı varsayılan KAPALI (WSS_THREAT_INTEL=1 ile varsayılan açılabilir)
THREAT_INTEL_DEFAULT = os.environ.get("WSS_THREAT_INTEL", "0").strip().lower() in ("1", "true", "yes", "on")
# Faz 5: gerçek tarayıcı (headless Chromium) varsayılan KAPALI (WSS_REAL_BROWSER=1 ile varsayılan açılabilir)
REAL_BROWSER_DEFAULT = headless_browser.browser_enabled_default()


def _flag(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")

class ScannerHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Statik dosyalar her zaman uygulama dizininden servis edilir (çalışma dizininden bağımsız).
        kwargs.setdefault("directory", APP_DIR)
        super().__init__(*args, **kwargs)

    def end_headers(self):
        # CORS başlığı GÖNDERİLMEZ: arayüz aynı kökenden servis edilir; başka sitelerin yerel API
        # yanıtlarını okuması tarayıcı tarafından engellenir (eski sürüm "Access-Control-Allow-Origin: *" gönderiyordu).
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    # ------------------------------------------------------------------
    # Yerel API güvenlik geçidi
    # ------------------------------------------------------------------
    def _request_hostname(self):
        host = self.headers.get("Host")
        if host is None:
            return None
        try:
            return (urllib.parse.urlsplit("//" + host.strip()).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""

    def _security_gate(self, method):
        """Host (tüm istekler) + köken, oturum anahtarı ve yöntem (/api/*) kontrolleri. Geçerse True döner."""
        path = urllib.parse.urlparse(self.path).path
        hostname = self._request_hostname()
        if hostname is not None and hostname not in ALLOWED_HOSTNAMES:
            self.send_json({"success": False, "error": "GECERSIZ_HOST",
                            "message": "İstek yalnızca yerel adreslerden (127.0.0.1 / localhost) kabul edilir "
                                       "(DNS rebinding koruması). Gerekirse WSS_ALLOWED_HOSTS ile ekleyin."}, status=403)
            return False
        if not path.startswith("/api/"):
            return True
        host_header = (self.headers.get("Host") or "").strip().lower()
        origin = self.headers.get("Origin")
        if origin is not None and origin.strip().lower() not in ("http://" + host_header, "https://" + host_header):
            self.send_json({"success": False, "error": "CAPRAZ_KOKEN_ENGELLENDI",
                            "message": "Yerel API'ye yalnızca arayüzün kendi kökeninden erişilebilir."}, status=403)
            return False
        fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if fetch_site and fetch_site not in ("same-origin", "none"):
            self.send_json({"success": False, "error": "CAPRAZ_KOKEN_ENGELLENDI",
                            "message": "Yerel API'ye başka sitelerden istek gönderilemez."}, status=403)
            return False
        supplied = (self.headers.get("X-WSS-Token") or "").strip()
        if not supplied:
            auth = (self.headers.get("Authorization") or "").strip()
            if auth.lower().startswith("bearer "):
                supplied = auth[7:].strip()
        if not supplied or not hmac.compare_digest(supplied.encode("utf-8"), API_TOKEN.encode("utf-8")):
            self.send_json({"success": False, "error": "WSS_TOKEN_GEREKLI",
                            "message": "Yerel API oturum anahtarı eksik veya geçersiz. Arayüz sayfasını yenileyin; "
                                       "CLI için sunucu açılışında yazdırılan anahtarı X-WSS-Token başlığıyla gönderin."},
                           status=401)
            return False
        if method == "GET" and path in POST_ONLY_API_PATHS:
            self.send_json({"success": False, "error": "YALNIZCA_POST",
                            "message": "Bu uç tarama başlattığı için yalnızca POST ile çağrılabilir."}, status=405)
            return False
        return True

    @staticmethod
    def _is_static_allowed(path):
        decoded = urllib.parse.unquote(path or "")
        if not decoded.startswith("/") or "\\" in decoded or "\x00" in decoded:
            return False
        segments = [s for s in decoded.split("/") if s]
        if any(s.startswith(".") for s in segments):
            return False  # .git, .env, ../ vb.
        if decoded.startswith(STATIC_ALLOWED_PREFIXES):
            return True
        return len(segments) == 1 and segments[0].lower().endswith(STATIC_ALLOWED_ROOT_EXT)

    def list_directory(self, path):
        # Dizin listeleme kapalı.
        self.send_error(404, "Not Found")
        return None

    def _serve_index(self):
        """index.html'i oturum anahtarı gömülü olarak servis eder (önbelleğe alınmaz)."""
        try:
            with open(os.path.join(APP_DIR, "index.html"), "r", encoding="utf-8") as fh:
                html = fh.read()
        except OSError:
            self.send_error(404, "index.html bulunamadı")
            return
        token_meta = '<meta name="wss-token" content="%s">' % API_TOKEN
        if TOKEN_META_PLACEHOLDER in html:
            html = html.replace(TOKEN_META_PLACEHOLDER, token_meta, 1)
        else:
            html = re.sub(r"(<head[^>]*>)", lambda m: m.group(1) + "\n    " + token_meta, html, count=1, flags=re.I)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        # CORS ön kontrolüne izin verilmez (Access-Control-Allow-* gönderilmez).
        hostname = self._request_hostname()
        if hostname is not None and hostname not in ALLOWED_HOSTNAMES:
            self.send_json({"success": False, "error": "GECERSIZ_HOST"}, status=403)
            return
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if not self._security_gate("POST"):
            return

        # Aktif tarama — yalnızca POST (parametreler sorgu dizesinde)
        if parsed.path == "/api/active-scan":
            self.handle_api_active_scan(parsed)
            return

        # Faz 3: Etik onay ucu — aktif test öncesi kullanıcı beyanı
        if parsed.path == "/api/active-confirm":
            self.handle_api_active_confirm()
            return

        # AI Red Team Orkestrasyonu (POST istekleri)
        if parsed.path == "/api/ai-scan":
            self.handle_api_ai_scan_post()
            return

        # AI Sağlayıcı Bağlantı Testi (OpenAI Compatible, Vertex, Gemini API vb.)
        if parsed.path == "/api/ai-test":
            self.handle_api_ai_test()
            return

        if parsed.path == "/api/ai-json-test":
            self.handle_api_ai_json_test()
            return

        if parsed.path == "/api/ai-chat":
            self.handle_api_ai_chat()
            return

        if parsed.path == "/api/ai-cancel":
            self.handle_api_ai_cancel()
            return

        if parsed.path == "/api/ai-note":
            self.handle_api_ai_note()
            return

        if parsed.path == "/api/ai-answer":
            self.handle_api_ai_answer()
            return

        if parsed.path == "/api/history-delete":
            self.handle_api_history_delete()
            return

        if parsed.path == "/api/update-apply":
            self.handle_api_update_apply()
            return

        # Strix AI Pentest: tarama başlat (alt süreç; etik onay zorunlu)
        if parsed.path == "/api/strix-scan":
            self.handle_api_strix_scan_post()
            return

        # Strix AI Pentest: taramayı iptal et
        if parsed.path == "/api/strix-cancel":
            self.handle_api_strix_cancel()
            return

        # Strix AI Pentest: CLI güncelleme (--update)
        if parsed.path == "/api/strix-update":
            self.handle_api_strix_update()
            return

        # Faz 2B: ersinkoc/security-check 4-Aşamalı AI Kaynak Kod Denetimi (POST /api/sast-ai)
        if parsed.path == "/api/sast-ai":
            self.handle_api_sast_ai()
            return

        if parsed.path in ("/api/php-advisory-remediate", "/api/php-remediate"):
            self.handle_api_php_advisory_remediate()
            return

        if parsed.path in ("/api/node-advisory-remediate", "/api/node-remediate"):
            self.handle_api_node_advisory_remediate()
            return

        self.send_json({"success": False, "error": "Bilinmeyen POST ucu"}, status=404)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if not self._security_gate("GET"):
            return

        # Sağlık kontrolü (Docker HEALTHCHECK) — oturum anahtarı gerektirmez, bilgi döndürmez.
        if parsed.path == "/healthz":
            self.send_json({"ok": True})
            return

        # 1. API: /api/headers?url=...
        if parsed.path == "/api/headers":
            self.handle_api_headers(parsed)
            return

        # 1b. API: /api/deep-scan?url=... (Derin Pasif Tarama - Faz 1)
        if parsed.path == "/api/deep-scan":
            self.handle_api_deep_scan(parsed)
            return

        # 1c. API: /api/sast?path=... (Kaynak Kod Analizi - Faz 2)
        if parsed.path == "/api/sast":
            self.handle_api_sast(parsed)
            return

        # 1c-2. API: /api/sast-dirs?q=... (Akıllı Dizin Arama & Otomatik Tamamlama)
        if parsed.path == "/api/sast-dirs":
            self.handle_api_sast_dirs(parsed)
            return

        # 1d. API: /api/active-scan?url=... (Aktif Güvenlik Testi - Faz 3)
        if parsed.path == "/api/active-scan":
            self.handle_api_active_scan(parsed)
            return

        # 1f. API: /api/strix-capabilities (Strix kurulum + özellik tespiti)
        if parsed.path == "/api/strix-capabilities":
            self.send_json(strix_capabilities())
            return

        # 1d. API: ajan talimatı varsayılanları (Faz 4)
        if parsed.path == "/api/ai-agent-prompts":
            self.handle_api_ai_agent_prompts()
            return

        # 1e. API: tarama geçmişi + fark (Faz 3)
        if parsed.path == "/api/history":
            self.handle_api_history(parsed)
            return
        if parsed.path == "/api/history-scan":
            self.handle_api_history_scan(parsed)
            return
        if parsed.path == "/api/history-diff":
            self.handle_api_history_diff(parsed)
            return

        # 1f. API: /api/ai-status?job=&since= (Faz 2 — canlı AI iş durumu + olay akışı)
        if parsed.path == "/api/ai-status":
            self.handle_api_ai_status(parsed)
            return

        # 1g. API: /api/strix-status?scan_id= (canlı durum + bulgu akışı)
        if parsed.path == "/api/strix-status":
            self.handle_api_strix_status(parsed)
            return

        # 1h. API: /api/strix-report?scan_id= (tam Strix raporu)
        if parsed.path == "/api/strix-report":
            self.handle_api_strix_report(parsed)
            return

        # 1i. API: /api/strix-runs (tarama listesi)
        if parsed.path == "/api/strix-runs":
            self.send_json({"success": True, "runs": STRIX_MANAGER.list_runs()})
            return

        # 1j. API: /api/strix-past-runs (diskteki tüm taramalar + resume listesi)
        if parsed.path == "/api/strix-past-runs":
            self.send_json({"success": True, "runs": STRIX_MANAGER.list_all_runs()})
            return

        # 1k. API: /api/update-check (GitHub main sürümüyle karşılaştır)
        if parsed.path == "/api/update-check":
            force = query.get("force", ["0"])[0].lower() in ("1", "true", "yes")
            info = updater.check_for_updates(APP_DIR, force=force)
            self.send_json(info)
            return

        # 2. API: /api/status (sunucu aktif mi ve hangi sürüm: lite vs full)
        if parsed.path == "/api/status":
            local_sha, _ = updater.local_commit_info(APP_DIR)
            self.send_json({
                "status": "online",
                "mode": "local_server",
                "edition": EDITION,
                "version": "2.0.0",
                "commit": local_sha[:7] if local_sha else "",
                "host": HOST,
                "real_browser": headless_browser.capabilities_nonblocking()
            })
            return

        # 3. Statik dosya sunumu — yalnızca arayüz dosyaları (kaynak kod, .git, rapor/test dizinleri servis edilmez)
        if parsed.path.startswith("/api/"):
            self.send_json({"success": False, "error": "Bilinmeyen GET ucu"}, status=404)
            return
        if parsed.path in ("/", "/index.html"):
            self._serve_index()
            return
        if not self._is_static_allowed(parsed.path):
            self.send_error(404, "Not Found")
            return
        super().do_GET()

    def handle_api_headers(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        raw_url = (qs.get("url") or [""])[0].strip()

        if not raw_url:
            self.send_json({"success": False, "error": "URL parametresi gereklidir (?url=https://...)"}, status=400)
            return

        # Şema kontrolü ve tamamlama
        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = "https://" + raw_url

        try:
            target = urllib.parse.urlparse(raw_url)
            if target.scheme not in ("http", "https"):
                self.send_json({"success": False, "error": "Yalnızca HTTP ve HTTPS protokolleri desteklenir."}, status=400)
                return

            if not target.netloc:
                self.send_json({"success": False, "error": "Geçersiz hedef alan adı."}, status=400)
                return

            # Pasif HTTP İsteği (Önce HEAD, 405 olursa GET fallback)
            headers_dict, status_code, final_url = self.fetch_headers(raw_url)

            self.send_json({
                "success": True,
                "url": raw_url,
                "final_url": final_url,
                "status_code": status_code,
                "headers": headers_dict
            })
        except urllib.error.HTTPError as e:
            # Hedef sunucu hata kodu dönse bile (örn. 403, 401, 500) başlıkları döndürebiliriz
            headers_dict = {k.lower(): v for k, v in e.headers.items()}
            self.send_json({
                "success": True,
                "url": raw_url,
                "final_url": e.geturl() if hasattr(e, "geturl") else raw_url,
                "status_code": e.code,
                "headers": headers_dict
            })
        except urllib.error.URLError as e:
            self.send_json({"success": False, "error": f"Bağlantı hatası: {e.reason}"}, status=502)
        except TimeoutError:
            self.send_json({"success": False, "error": f"Zaman aşımı: Hedef sunucu {TIMEOUT_SECONDS} saniye içinde yanıt vermedi."}, status=504)
        except Exception as e:
            self.send_json({"success": False, "error": f"Beklenmeyen hata: {str(e)}"}, status=500)

    # =============================================================
    # FAZ 1: Derin Pasif Tarama Uç Noktası (/api/deep-scan)
    # Çerez analizi + TLS/sertifika + robots.txt ifşası + mixed content + teknoloji parmak izi
    # =============================================================
    def handle_api_deep_scan(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        raw_url = (qs.get("url") or [""])[0].strip()

        if not raw_url:
            self.send_json({"success": False, "error": "URL parametresi gereklidir"}, status=400)
            return
        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = "https://" + raw_url

        result = {
            "success": True,
            "url": raw_url,
            "cookies": {"analyzed": False, "findings": []},
            "tls": {"analyzed": False, "findings": []},
            "robots": {"analyzed": False, "findings": []},
            "mixed_content": {"analyzed": False, "findings": []},
            "tech_fingerprint": {"analyzed": False, "technologies": []}
        }

        try:
            parsed_target = urllib.parse.urlparse(raw_url)
            hostname = parsed_target.hostname
            is_https = parsed_target.scheme == "https"

            # 1.1 Çerez Güvenlik Analizi (Set-Cookie başlıklarından)
            try:
                req = urllib.request.Request(raw_url, headers={"User-Agent": USER_AGENT}, method="GET")
                with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                    set_cookies = resp.headers.get_all("Set-Cookie") or []
                    html_body = resp.read(512 * 1024).decode("utf-8", errors="replace")  # max 512KB
                    final_headers = {k.lower(): v for k, v in resp.headers.items()}

                cookie_findings = []
                for cookie_raw in set_cookies:
                    parts = cookie_raw.split(";")
                    name_val = parts[0].strip()
                    cname = name_val.split("=")[0].strip() if "=" in name_val else name_val
                    attrs = {p.strip().split("=")[0].strip().lower(): (p.strip().split("=")[1].strip() if "=" in p.strip() else "") for p in parts[1:]}
                    finding = {
                        "name": cname,
                        "httponly": "httponly" in attrs,
                        "secure": "secure" in attrs,
                        "samesite": attrs.get("samesite", "(belirtilmemiş)"),
                        "issues": []
                    }
                    if not finding["httponly"]:
                        finding["issues"].append("HttpOnly bayrağı yok — XSS ile çalınabilir")
                    if not finding["secure"]:
                        finding["issues"].append("Secure bayrağı yok — düz HTTP üzerinden gönderilebilir")
                    if attrs.get("samesite", "").lower() not in ("strict", "lax"):
                        finding["issues"].append("SameSite Strict/Lax değil — CSRF riski")
                    cookie_findings.append(finding)

                result["cookies"] = {"analyzed": True, "count": len(cookie_findings), "findings": cookie_findings}
            except Exception as e:
                result["cookies"] = {"analyzed": False, "error": str(e), "findings": []}

            # 1.2 TLS / Sertifika & Cipher Suite / PFS Analizi (yalnızca HTTPS hedeflerde)
            if is_https:
                try:
                    ctx = ssl.create_default_context()
                    tls_port = parsed_target.port or 443
                    with socket.create_connection((hostname, tls_port), timeout=TIMEOUT_SECONDS) as sock:
                        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                            cert = tls_sock.getpeercert()
                            tls_version = tls_sock.version()
                            cipher_info = tls_sock.cipher()  # (cipher_name, tls_proto, secret_bits)
                            compression = tls_sock.compression()

                    import datetime
                    not_after = cert.get("notAfter", "")
                    expiry_days = None
                    if not_after:
                        try:
                            exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                            expiry_days = (exp_date - datetime.datetime.now(datetime.timezone.utc)).days
                        except Exception:
                            pass

                    cipher_name = cipher_info[0] if cipher_info else ""
                    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else None
                    upper_cipher = (cipher_name or "").upper()
                    has_pfs = (
                        tls_version == "TLSv1.3"
                        or "ECDHE" in upper_cipher
                        or "DHE" in upper_cipher
                        or upper_cipher.startswith("TLS_AES_")
                        or upper_cipher.startswith("TLS_CHACHA20_")
                    )

                    tls_findings = []
                    if expiry_days is not None and expiry_days < 30:
                        tls_findings.append({"level": "YÜKSEK" if expiry_days < 7 else "ORTA", "issue": f"Sertifika {expiry_days} gün içinde sona eriyor", "evidence": not_after})
                    if tls_version and tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        tls_findings.append({"level": "YÜKSEK", "issue": f"Eski TLS protokolü: {tls_version} (POODLE/BEAST riski)", "evidence": "TLS 1.0/1.1 kullanımdan kaldırıldı; TLS 1.2+ zorunlu kılın"})

                    # Claude-Red offensive-tls-attacks: Zayıf Cipher Suite & PFS & CRIME denetimi
                    if any(w in upper_cipher for w in ("RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "MD5")):
                        tls_findings.append({"level": "KRİTİK", "issue": f"Kırılmış/Zayıf TLS Cipher Suite aktif: {cipher_name}", "evidence": f"{cipher_name} ({cipher_bits} bit) — SWEET32/RC4 saldırılarına açık"})
                    elif "CBC" in upper_cipher and tls_version != "TLSv1.3":
                        tls_findings.append({"level": "DÜŞÜK", "issue": f"CBC modlu Cipher Suite kullanımı ({cipher_name})", "evidence": "Lucky13 / Padding Oracle riskine karşı AEAD (AES-GCM / ChaCha20-Poly1305) tercih edin"})
                    if cipher_bits is not None and cipher_bits < 128:
                        tls_findings.append({"level": "YÜKSEK", "issue": f"Düşük simetrik anahtar uzunluğu ({cipher_bits} bit)", "evidence": cipher_name})
                    if cipher_name and not has_pfs:
                        tls_findings.append({"level": "ORTA", "issue": "Perfect Forward Secrecy (PFS / ECDHE) desteği yok", "evidence": f"Anlaşılan şifreleme: {cipher_name} (Statik RSA anahtar değişimi geçmiş trafiğin deşifre edilmesine yol açar)"})
                    if compression:
                        tls_findings.append({"level": "YÜKSEK", "issue": f"TLS Sıkıştırma (Compression) aktif: {compression}", "evidence": "CRIME / BREACH yan kanal saldırılarına karşı TLS sıkıştırmasını kapatın"})

                    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"] if cert else []
                    if hostname not in sans and not any(s.startswith("*.") and hostname.endswith(s[1:]) for s in sans):
                        tls_findings.append({"level": "ORTA", "issue": "Hostname SAN listesinde birebir eşleşmiyor", "evidence": ", ".join(sans[:5])})

                    result["tls"] = {
                        "analyzed": True,
                        "protocol": tls_version,
                        "cipher_suite": cipher_name,
                        "cipher_bits": cipher_bits,
                        "pfs_supported": has_pfs,
                        "compression": compression,
                        "issuer": dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "(bilinmiyor)"),
                        "valid_until": not_after,
                        "expiry_days": expiry_days,
                        "san_count": len(sans),
                        "findings": tls_findings
                    }
                except Exception as e:
                    result["tls"] = {"analyzed": False, "error": str(e), "findings": []}
            else:
                result["tls"] = {"analyzed": True, "findings": [{"level": "YÜKSEK", "issue": "Hedef HTTPS kullanmıyor", "evidence": "http:// şeması"}]}

            # 1.3 robots.txt İfşası Taraması
            try:
                robots_url = f"{parsed_target.scheme}://{parsed_target.netloc}/robots.txt"
                req = urllib.request.Request(robots_url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                    robots_text = resp.read(64 * 1024).decode("utf-8", errors="replace")

                sensitive_patterns = [
                    (r"Disallow:\s*/admin", "/admin dizini ifşa edilmiş"),
                    (r"Disallow:\s*/wp-(login|admin)", "WordPress yönetim paneli ifşa edilmiş"),
                    (r"Disallow:\s*/\.env", ".env dosyası (sır depolama) ifşa edilmiş"),
                    (r"Disallow:\s*/config", "/config dizini ifşa edilmiş"),
                    (r"Disallow:\s*/backup", "/backup dizini ifşa edilmiş"),
                    (r"Disallow:\s*/db|sql|dump", "veritabanı/dump dizini ifşa edilmiş"),
                    (r"Disallow:\s*/private|secret", "özel/gizli dizin ifşa edilmiş"),
                    (r"Disallow:\s*/api", "/api kökü ifşa edilmiş"),
                ]
                robots_findings = []
                for pattern, desc in sensitive_patterns:
                    matches = re.findall(pattern, robots_text, re.IGNORECASE)
                    if matches:
                        robots_findings.append({"level": "DÜŞÜK", "issue": f"robots.txt: {desc}", "evidence": matches[0][:80]})

                result["robots"] = {"analyzed": True, "exists": True, "findings": robots_findings, "raw_size": len(robots_text)}
            except urllib.error.HTTPError as e:
                result["robots"] = {"analyzed": True, "exists": False, "findings": [], "note": f"robots.txt yok (HTTP {e.code})"}
            except Exception as e:
                result["robots"] = {"analyzed": False, "error": str(e), "findings": []}

            # 1.4 Mixed Content Tespiti (HTML gövdesinden)
            if html_body:
                http_resources = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', html_body)
                # Yalnızca aktif içerik (script/iframe/img değil; script ve iframe kritik)
                mixed_findings = []
                scripts_http = re.findall(r'<script[^>]+src=["\'](http://[^"\']+)["\']', html_body)
                iframes_http = re.findall(r'<iframe[^>]+src=["\'](http://[^"\']+)["\']', html_body)
                for u in scripts_http[:5]:
                    mixed_findings.append({"level": "YÜKSEK", "issue": "HTTP kaynaktan script yükleniyor (active mixed content)", "evidence": u[:120]})
                for u in iframes_http[:5]:
                    mixed_findings.append({"level": "YÜKSEK", "issue": "HTTP kaynaktan iframe yükleniyor", "evidence": u[:120]})
                passive_http = [u for u in http_resources if u not in scripts_http and u not in iframes_http][:5]
                for u in passive_http:
                    mixed_findings.append({"level": "DÜŞÜK", "issue": "HTTP kaynaktan pasif içerik (img/css) yükleniyor", "evidence": u[:120]})
                result["mixed_content"] = {"analyzed": True, "is_https_target": is_https, "findings": mixed_findings}
            else:
                result["mixed_content"] = {"analyzed": False, "findings": [], "note": "HTML gövdesi alınamadı"}

            # 1.5 Teknoloji Parmak İzi (headers + HTML meta + cookie isimleri)
            techs = []
            server_h = final_headers.get("server", "")
            xpb_h = final_headers.get("x-powered-by", "")
            if server_h:
                techs.append({"category": "Web Sunucusu", "value": server_h[:80], "source": "Server başlığı"})
            if xpb_h:
                techs.append({"category": "Çalışma Ortamı", "value": xpb_h[:80], "source": "X-Powered-By başlığı"})
            if html_body:
                generators = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
                if not generators:
                    generators = re.findall(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', html_body, re.IGNORECASE)
                for g in generators[:3]:
                    techs.append({"category": "CMS/Framework", "value": g[:80], "source": "meta generator"})
                if re.search(r'wp-content|wp-includes', html_body):
                    techs.append({"category": "CMS", "value": "WordPress", "source": "wp-content kalıbı"})
                if re.search(r'__NEXT_DATA__|/_next/', html_body):
                    techs.append({"category": "Framework", "value": "Next.js", "source": "__NEXT_DATA__ kalıbı"})
                if re.search(r'ng-version|angular\.min\.js', html_body):
                    techs.append({"category": "Framework", "value": "Angular", "source": "ng-version kalıbı"})
                if re.search(r'data-react|react\.production', html_body):
                    techs.append({"category": "Framework", "value": "React", "source": "react kalıbı"})
                for fmark, fname in (("cloudflare", "Cloudflare CDN"), ("amazonaws", "AWS S3/CloudFront"), ("googleusercontent", "Google Cloud")):
                    if fmark in html_body[:20480]:
                        techs.append({"category": "CDN/Bulut", "value": fname, "source": "HTML kalıbı"})
            # WAF / CDN Başlık Parmak İzi (Claude-Red offensive-waf-bypass için)
            if "cf-ray" in final_headers or "cloudflare" in server_h.lower():
                techs.append({"category": "WAF/CDN", "value": "Cloudflare WAF", "source": "CF-Ray / Server başlığı"})
            if "x-amzn-requestid" in final_headers or "x-amz-cf-id" in final_headers:
                techs.append({"category": "WAF/CDN", "value": "AWS CloudFront / WAF", "source": "X-Amz başlığı"})
            if "x-iinfo" in final_headers or "incap_ses" in str(final_headers.get("set-cookie", "")):
                techs.append({"category": "WAF/CDN", "value": "Imperva Incapsula WAF", "source": "X-Iinfo / çerez"})
            if "akamai" in server_h.lower() or "x-akamai-transformed" in final_headers:
                techs.append({"category": "WAF/CDN", "value": "Akamai WAF/CDN", "source": "Akamai başlığı"})
            if "mod_security" in server_h.lower() or "modsecurity" in server_h.lower():
                techs.append({"category": "WAF", "value": "ModSecurity WAF", "source": "Server başlığı"})
            for c in result["cookies"].get("findings", []):
                if c["name"].lower().startswith(("wp-", "wordpress_")):
                    techs.append({"category": "CMS", "value": "WordPress", "source": "çerez adı"})
                if "laravel" in c["name"].lower():
                    techs.append({"category": "Framework", "value": "Laravel", "source": "çerez adı"})
                if "phpsessid" == c["name"].lower():
                    techs.append({"category": "Dil", "value": "PHP", "source": "çerez adı"})
                if "jsessionid" == c["name"].lower():
                    techs.append({"category": "Dil", "value": "Java", "source": "çerez adı"})
                if "connect.sid" == c["name"].lower():
                    techs.append({"category": "Framework", "value": "Express.js", "source": "çerez adı"})

            result["tech_fingerprint"] = {"analyzed": True, "technologies": techs}

            self.send_json(result)

        except urllib.error.URLError as e:
            self.send_json({"success": False, "error": f"Bağlantı hatası: {e.reason}"}, status=502)
        except Exception as e:
            self.send_json({"success": False, "error": f"Beklenmeyen hata: {str(e)}"}, status=500)

    # =============================================================
    # FAZ 2: SAST — Kaynak Kod Analizi Uç Noktası (/api/sast)
    # Dizin taraması (42 kural) + bağımlılık CVE kontrolü (OSV)
    # =============================================================
    def _get_sast_search_roots(self):
        home = os.path.expanduser("~")
        cwd = os.getcwd()
        ws_root = os.environ.get("WSS_WORKSPACE_ROOT") or "/workspace"
        common_subdirs = ("Projects", "projects", "Developer", "Desktop", "Documents", "repos", "workspace", "src", "www")
        candidates = [
            ws_root,
            *[os.path.join(ws_root, sub) for sub in common_subdirs],
            cwd,
            os.path.dirname(cwd),
            os.path.dirname(os.path.dirname(cwd)),
            home,
            *[os.path.join(home, sub) for sub in common_subdirs],
            "/var/www",
            "/var/www/html",
            "/srv",
            "/opt",
            "/www/wwwroot",
        ]
        roots = []
        seen = set()
        for r in candidates:
            if not r:
                continue
            ar = os.path.abspath(r)
            if ar not in seen and os.path.isdir(ar):
                seen.add(ar)
                roots.append(ar)
        return roots

    def _search_matching_dirs(self, query="", max_results=20):
        """Klasör adına (tam yol vermeden) göre 2 seviye derinlikte hızlı dizin araması yapar."""
        q = (query or "").strip()
        expanded = os.path.expanduser(q) if q else ""
        exact_matches = []
        prefix_matches = []
        substr_matches = []
        seen = set()

        skip_names = {
            ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
            "dist", "build", ".next", ".nuxt", "target", ".idea", ".vscode",
            "coverage", ".cache", "Library", ".Trash", ".npm", ".cargo", ".rustup"
        }

        if expanded and os.path.isdir(expanded):
            ap = os.path.abspath(expanded)
            seen.add(ap)
            exact_matches.append(ap)

        stripped = q.strip("/").strip()
        q_lower = stripped.lower()
        base_q = os.path.basename(stripped).lower()

        roots = self._get_sast_search_roots()

        # 1) Doğrudan kök + stripped birleşimi
        if stripped:
            for r in roots:
                cand = os.path.join(r, stripped)
                if os.path.isdir(cand):
                    ap = os.path.abspath(cand)
                    if ap not in seen:
                        seen.add(ap)
                        exact_matches.append(ap)

        # 2) Köklerin altındaki 1. ve 2. seviye klasörleri tara (büyük/küçük harf duyarsız + kısmi eşleşme)
        for r in roots:
            try:
                lvl1 = sorted(os.listdir(r))[:120]
            except OSError:
                continue
            for name1 in lvl1:
                if name1.startswith(".") or name1 in skip_names:
                    continue
                full1 = os.path.join(r, name1)
                if not os.path.isdir(full1):
                    continue
                ap1 = os.path.abspath(full1)
                n1_low = name1.lower()
                if not base_q:
                    if ap1 not in seen:
                        seen.add(ap1)
                        prefix_matches.append(ap1)
                else:
                    if n1_low == base_q or n1_low == q_lower:
                        if ap1 not in seen:
                            seen.add(ap1)
                            exact_matches.append(ap1)
                    elif n1_low.startswith(base_q):
                        if ap1 not in seen:
                            seen.add(ap1)
                            prefix_matches.append(ap1)
                    elif base_q in n1_low:
                        if ap1 not in seen:
                            seen.add(ap1)
                            substr_matches.append(ap1)

                # 2. seviye (yalnızca sorgu varsa veya proje kökleriyse)
                if base_q and len(exact_matches) < max_results:
                    try:
                        lvl2 = sorted(os.listdir(full1))[:80]
                    except OSError:
                        continue
                    for name2 in lvl2:
                        if name2.startswith(".") or name2 in skip_names:
                            continue
                        n2_low = name2.lower()
                        if base_q not in n2_low:
                            continue
                        full2 = os.path.join(full1, name2)
                        if not os.path.isdir(full2):
                            continue
                        ap2 = os.path.abspath(full2)
                        if ap2 in seen:
                            continue
                        seen.add(ap2)
                        if n2_low == base_q:
                            exact_matches.append(ap2)
                        elif n2_low.startswith(base_q):
                            prefix_matches.append(ap2)
                        else:
                            substr_matches.append(ap2)

        combined = exact_matches + prefix_matches + substr_matches
        return combined[:max_results]

    def _resolve_sast_path(self, raw_path):
        matches = self._search_matching_dirs(raw_path, max_results=15)
        if matches:
            return matches[0], matches
        available = self._search_matching_dirs("", max_results=15)
        return None, available

    def handle_api_sast_dirs(self, parsed_path):
        """Klasör adına göre tam dizin yolunu bulur ve otomatik tamamlama önerileri döndürür."""
        qs = urllib.parse.parse_qs(parsed_path.query)
        q = (qs.get("q") or [""])[0].strip()
        matches = self._search_matching_dirs(q, max_results=20)
        self.send_json({
            "success": True,
            "query": q,
            "resolved": matches[0] if matches else None,
            "matches": matches
        })

    def handle_api_sast(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        raw_path = (qs.get("path") or [""])[0].strip()
        profile = (qs.get("profile") or ["standard"])[0].strip()
        scope_mode = (qs.get("scope_mode") or ["full"])[0].strip()
        diff_base = (qs.get("diff_base") or ["HEAD"])[0].strip()

        if not raw_path:
            self.send_json({"success": False, "error": "path parametresi gereklidir (?path=/proje/dizini)"}, status=400)
            return

        resolved_path, available = self._resolve_sast_path(raw_path)
        if not resolved_path:
            self.send_json({
                "success": False,
                "error": f"Dizin bulunamadı: {raw_path}",
                "available_dirs": available
            }, status=404)
            return

        try:
            from sast_engine import sast_scan_directory, check_dependencies_osv, _build_security_check_artifacts

            scan_result = sast_scan_directory(resolved_path, profile=profile, scope_mode=scope_mode, diff_base=diff_base)
            scan_result["resolved_path"] = resolved_path

            deps_result = None
            if (qs.get("deps") or ["1"])[0] in ("1", "true", "yes"):
                try:
                    deps_result = check_dependencies_osv(resolved_path)
                except Exception as e:
                    deps_result = {"analyzed": False, "error": str(e)[:200]}

            scan_result["dependencies"] = deps_result
            if deps_result and scan_result.get("security_check"):
                sc = scan_result["security_check"]
                files_list = [f.get("file") for f in (scan_result.get("findings") or []) if f.get("file")]
                updated_sc = _build_security_check_artifacts(
                    resolved_path, scan_result.get("findings") or [], deps_result,
                    files_list, [], profile, scope_mode, diff_base
                )
                sc["dependency_audit_md"] = updated_sc["dependency_audit_md"]
                sc["security_report_md"] = updated_sc["security_report_md"]
            self.send_json(scan_result)

        except Exception as e:
            self.send_json({"success": False, "error": f"SAST taraması başarısız: {str(e)}"}, status=500)


    def handle_api_php_advisory_remediate(self):
        """Proje dizinindeki PHP yapılandırmalarına CVE-2026-109618 / CVE-2026-109619 otomatik düzeltmelerini uygular."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        raw_path = (data.get("path") or "").strip()
        apply_fixes = data.get("apply") is not False
        if not raw_path:
            self.send_json({"success": False, "error": "path alanı gereklidir"}, status=400)
            return

        resolved_path, available = self._resolve_sast_path(raw_path)
        if not resolved_path:
            self.send_json({"success": False, "error": f"Dizin bulunamadı: {raw_path}", "available_dirs": available}, status=404)
            return

        try:
            from sast_engine import remediate_php_advisory_directory
            res = remediate_php_advisory_directory(resolved_path, apply_fixes=apply_fixes)
            self.send_json(res)
        except Exception as e:
            self.send_json({"success": False, "error": f"PHP otomatik düzeltme hatası: {str(e)}"}, status=500)

    def handle_api_node_advisory_remediate(self):
        """Proje dizinindeki Node.js yapılandırmalarına 21 Ekim 2026 güvenlik bülteni düzeltmelerini uygular."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        raw_path = (data.get("path") or "").strip()
        apply_fixes = data.get("apply") is not False
        if not raw_path:
            self.send_json({"success": False, "error": "path alanı gereklidir"}, status=400)
            return

        resolved_path, available = self._resolve_sast_path(raw_path)
        if not resolved_path:
            self.send_json({"success": False, "error": f"Dizin bulunamadı: {raw_path}", "available_dirs": available}, status=404)
            return

        try:
            from sast_engine import remediate_node_advisory_directory
            res = remediate_node_advisory_directory(resolved_path, apply_fixes=apply_fixes)
            self.send_json(res)
        except Exception as e:
            self.send_json({"success": False, "error": f"Node.js otomatik düzeltme hatası: {str(e)}"}, status=500)

    def handle_api_sast_ai(self):
        """ersinkoc/security-check 4-Aşamalı AI Kaynak Kod Denetimi (Recon -> Hunt -> Verify -> Report)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        raw_path = (data.get("path") or "").strip()
        profile = (data.get("profile") or "standard").strip()
        scope_mode = (data.get("scope_mode") or "full").strip()
        diff_base = (data.get("diff_base") or "HEAD").strip()
        ai_config = data.get("ai_config") or {}

        if not raw_path:
            self.send_json({"success": False, "error": "path alanı gereklidir"}, status=400)
            return

        resolved_path, available = self._resolve_sast_path(raw_path)
        if not resolved_path:
            self.send_json({
                "success": False,
                "error": f"Dizin bulunamadı: {raw_path}",
                "available_dirs": available
            }, status=404)
            return

        try:
            from sast_engine import run_ai_sast_audit
            res = run_ai_sast_audit(resolved_path, ai_config, profile=profile, scope_mode=scope_mode, diff_base=diff_base)
            res["resolved_path"] = resolved_path
            self.send_json(res, status=200 if res.get("success") else 400)
        except Exception as e:
            self.send_json({"success": False, "error": f"AI SAST hatası: {str(e)}"}, status=500)

    # =============================================================
    # FAZ 3: Aktif Güvenlik Testi Uçları
    # Etik onay (POST /api/active-confirm) + tarama (GET /api/active-scan)
    # =============================================================
    def handle_api_active_confirm(self):
        """Kullanıcının etik beyanını alır ve domain için onay kaydeder."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        raw_url = (data.get("url") or "").strip()
        confirmed = data.get("confirmed") is True

        if not raw_url:
            self.send_json({"success": False, "error": "url alanı gereklidir"}, status=400)
            return
        if not confirmed:
            self.send_json({"success": False, "error": "Onay bayrağı (confirmed: true) gereklidir"}, status=400)
            return

        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = "https://" + raw_url

        try:
            hostname = urllib.parse.urlparse(raw_url).hostname
        except ValueError:
            hostname = None

        if not hostname:
            self.send_json({"success": False, "error": "Geçersiz hedef adres"}, status=400)
            return

        ETHICAL_GATE.confirm(hostname)
        self.send_json({
            "success": True,
            "message": "Etik onay kaydedildi: %s için aktif test yetkisi verildi." % hostname,
            "domain": hostname
        })

    def handle_api_active_scan(self, parsed_path):
        """Etik onay sonrası aktif taramayı yürütür."""
        qs = urllib.parse.parse_qs(parsed_path.query)
        raw_url = (qs.get("url") or [""])[0].strip()
        modules_param = (qs.get("modules") or [""])[0].strip()

        if not raw_url:
            self.send_json({"success": False, "error": "URL parametresi gereklidir"}, status=400)
            return

        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = "https://" + raw_url

        modules = [m for m in modules_param.split(",") if m] if modules_param else None
        threat_flag = _flag((qs.get("threat_intel") or [""])[0]) or THREAT_INTEL_DEFAULT
        real_browser_flag = _flag((qs.get("real_browser") or [""])[0]) or REAL_BROWSER_DEFAULT

        try:
            result = run_active_scan(raw_url, modules, options={"real_browser": real_browser_flag})
            if not result.get("success") and result.get("error") == "ETIK_ONAY_YOK":
                self.send_json({
                    "success": False,
                    "error": "ETIK_ONAY_YOK",
                    "message": "Aktif test öncesi etik onay gereklidir. Lütfen onay diyaloğunu kabul edin."
                }, status=403)
                return
            if result.get("success"):
                self._post_scan_enrichment(result, raw_url, "active", threat_flag)
            self.send_json(result)
        except Exception as e:
            self.send_json({"success": False, "error": "Aktif tarama başarısız: %s" % str(e)}, status=500)

    def _post_scan_enrichment(self, result, url, kind, threat_flag=False, emit=None):
        """Faz 3: (isteğe bağlı) tehdit istihbaratı + tarama geçmişi kaydı + önceki taramaya göre fark.

        Hiçbir hata taramanın sonucunu bozmaz; sorun result içine not edilir. İptal edilen ya da
        başarısız taramalar kaydedilmez (yanıltıcı "kapanan bulgu" farkı üretmemek için).
        """
        if not isinstance(result, dict) or not result.get("success") or result.get("cancelled"):
            return result
        if threat_flag:
            try:
                # Etik onaylı hedefe tek, kapsam kilitli GET: başlıklar + ana sayfa HTML'i
                probe = RateLimitedClient(scope_url=url, max_requests=1).get(url)
                headers = probe.get("headers") if isinstance(probe.get("headers"), dict) else {}
                intel_findings, intel_summary = threat_intel.run_threat_intel(
                    headers=headers, html=probe.get("body") or "", emit=emit)
                intel_summary["findings"] = intel_findings
                result["threat_intel"] = intel_summary
                bucket = "baseline_findings" if kind == "ai" else "findings"
                result.setdefault(bucket, [])
                result[bucket].extend(intel_findings)
                if kind != "ai":
                    # Sayaçlar ve yaşam döngüsü tarama sonunda hesaplandığı için istihbarat bulgularını
                    # buraya da ekle (aksi hâlde liste ile önem sayaçları / lifecycle tutarsız kalır).
                    summary = result.get("summary")
                    if isinstance(summary, dict):
                        for f in intel_findings:
                            summary[f.get("severity")] = int(summary.get(f.get("severity")) or 0) + 1
                    lifecycle = result.get("lifecycle")
                    if isinstance(lifecycle, dict) and isinstance(lifecycle.get("needs_validation"), list):
                        lifecycle["needs_validation"].extend(intel_findings)
            except Exception as e:
                result["threat_intel"] = {"enabled": True, "findings": [],
                                          "errors": ["Tehdit istihbaratı çalıştırılamadı: %s" % str(e)[:160]]}
        try:
            hist_findings = list(result.get("findings") or [])
            meta = {"threat_intel": bool(threat_flag)}
            modules = result.get("modules")
            if isinstance(modules, dict) and len(json.dumps(modules, default=str)) <= 20000:
                meta["modules"] = modules
            if kind == "ai":
                hist_findings += list(result.get("baseline_findings") or [])
                rep = result.get("ai_report") or {}
                meta["ai"] = {
                    "loops": rep.get("loops"), "tests_executed": rep.get("tests_executed"),
                    # Probe günlüğü (PentAGI kalıcı komut/çıktı kaydı uyarlaması): ne denendi, karar ne oldu.
                    # Yanıt gövdeleri saklanmaz; record_scan her şeyi redact_obj ile maskeler.
                    "executed_tests": [
                        {"url": str(t.get("url", ""))[:200], "param": str(t.get("param", ""))[:80],
                         "payload": str(t.get("payload", ""))[:160], "verdict": t.get("verdict"), "loop": t.get("loop")}
                        for t in (rep.get("executed_tests") or [])[:60] if isinstance(t, dict)],
                    "telemetry_by_agent": (rep.get("telemetry") or {}).get("by_agent"),
                }
            recorded = scan_history.record_scan(
                kind, url, hist_findings,
                summary={"requests_sent": result.get("requests_sent"), "duration_ms": result.get("duration_ms")},
                meta=meta)
            result["history"] = recorded if recorded else {"enabled": False}
        except Exception as e:
            result["history"] = {"enabled": True, "error": "Tarama geçmişine yazılamadı: %s" % str(e)[:160]}
        return result

    def handle_api_history(self, parsed_path):
        """Faz 3: hedef / tür bazında tarama geçmişi listesi (yeniden eskiye)."""
        qs = urllib.parse.parse_qs(parsed_path.query)
        target = (qs.get("target") or [""])[0].strip()
        kind = (qs.get("kind") or [""])[0].strip()
        try:
            scans = scan_history.list_scans(target=target or None, kind=kind or None,
                                            limit=(qs.get("limit") or ["50"])[0])
            self.send_json({"success": True, "enabled": scan_history.history_enabled(),
                            "retention_days": scan_history.retention_days(), "scans": scans})
        except Exception as e:
            self.send_json({"success": False, "error": "Geçmiş okunamadı: %s" % str(e)[:160]}, status=500)

    def handle_api_history_scan(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        scan = scan_history.get_scan((qs.get("id") or [""])[0].strip())
        if not scan:
            self.send_json({"success": False, "error": "SCAN_NOT_FOUND"}, status=404)
            return
        self.send_json({"success": True, "scan": scan})

    def handle_api_history_diff(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        diff = scan_history.diff_scans((qs.get("id") or [""])[0].strip(),
                                       (qs.get("base") or [""])[0].strip() or None)
        if not diff:
            self.send_json({"success": False, "error": "SCAN_NOT_FOUND"}, status=404)
            return
        self.send_json({"success": True, "diff": diff})

    def handle_api_update_apply(self):
        res = updater.apply_update(APP_DIR)
        status_code = 200 if res.get("ok") else 500
        self.send_json(res, status=status_code)
        if res.get("ok") and res.get("restarting") and os.environ.get("WSS_DISABLE_EXEC_RESTART") != "1":
            def _restart_proc():
                time.sleep(0.8)
                try:
                    self.server.server_close()
                except Exception:
                    pass
                try:
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                except Exception:
                    pass
            threading.Thread(target=_restart_proc, daemon=True).start()

    def handle_api_history_delete(self):
        data = self._read_json_payload()
        if data is None:
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return
        if data.get("id"):
            deleted = scan_history.delete_scan(str(data["id"]))
        elif data.get("target"):
            deleted = scan_history.delete_target(str(data["target"]))
        elif data.get("all") is True:
            deleted = scan_history.delete_all()
        else:
            self.send_json({"success": False, "error": "id, target ya da \"all\": true gereklidir."}, status=400)
            return
        self.send_json({"success": True, "deleted": deleted})

    def handle_api_ai_test(self):
        """AI Sağlayıcı bağlantısını test eder (OpenAI Compatible, Vertex, Gemini API vb.)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        provider_config = data.get("ai_config") or data
        try:
            connector = AIProviderFactory.create_connector(provider_config)
            test_res = connector.test_connection()
            self.send_json(test_res)
        except Exception as e:
            self.send_json({"success": False, "error": f"Bağlantı hatası: {str(e)}"}, status=400)

    def handle_api_ai_chat(self):
        """Faz 4: tarama bulguları hakkında salt-okunur güvenlik sohbet asistanı."""
        data = self._read_json_payload()
        if data is None:
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return
        try:
            result = security_assistant.answer_question(
                data.get("ai_config") or {}, data.get("question"),
                context=data.get("context"), history=data.get("history"))
            self.send_json(result, status=200 if result.get("success") else 400)
        except Exception as e:
            self.send_json({"success": False, "error": "Asistan hatası: %s" % str(e)[:200]}, status=500)

    def handle_api_ai_agent_prompts(self):
        """Faz 4: düzenlenebilir ajan talimatlarının varsayılanları (arayüz bunları gösterir/düzenler)."""
        import ai_orchestrator
        self.send_json({
            "success": True,
            "defaults": ai_orchestrator.DEFAULT_AGENT_PROMPTS,
            "roles": list(ai_orchestrator._ROLE_NAMES),
            "locked_note": ("Her talimata değiştirilemez bir güvenlik eki eklenir. Kapsam (yalnız onaylı "
                            "host:port), yıkıcı payload reddi ve durum değiştiren uçlar için operatör onayı "
                            "KODDA zorlanır; talimat ne derse desin bu kurallar geçerlidir."),
        })

    def handle_api_ai_json_test(self):
        """AI saglayici/modelin JSON modu uyumlulugunu olcer (Faz 1 — json_health_check).

        Dondurur: success, json_quality (clean|repaired|fixer_retry|parse_failed),
        repaired, fixer_retry_used, keys_returned, latency_ms.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        provider_config = data.get("ai_config") or data
        try:
            connector = AIProviderFactory.create_connector(provider_config)
            result = connector.json_health_check()
            self.send_json(result)
        except Exception as e:
            self.send_json({"success": False, "error": f"Bağlantı hatası: {str(e)}"}, status=400)

    def _read_json_payload(self):
        """İstek gövdesini JSON olarak okur; geçersizse None döner."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
            return data if isinstance(data, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def _ai_job_or_error(self, job_id):
        job = AI_JOBS.get(job_id)
        if not job:
            self.send_json({"success": False, "error": "JOB_NOT_FOUND",
                            "message": "AI işi bulunamadı (süresi dolmuş ya da sunucu yeniden başlatılmış olabilir)."},
                           status=404)
        return job

    def handle_api_ai_status(self, parsed_path):
        """Faz 2: arka plan AI işinin durumu + 'since' sonrasındaki olaylar + bekleyen soru."""
        qs = urllib.parse.parse_qs(parsed_path.query)
        job = self._ai_job_or_error((qs.get("job") or [""])[0].strip())
        if not job:
            return
        self.send_json(job.view((qs.get("since") or ["0"])[0]))

    def handle_api_ai_cancel(self):
        data = self._read_json_payload()
        if data is None:
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return
        job = self._ai_job_or_error(str(data.get("job_id") or ""))
        if not job:
            return
        ok = job.cancel()
        self.send_json({"success": ok, "status": job.status,
                        "message": "İptal istendi; o anki adım bitince duracak." if ok else "İş zaten tamamlanmış."})

    def handle_api_ai_note(self):
        data = self._read_json_payload()
        if data is None:
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return
        job = self._ai_job_or_error(str(data.get("job_id") or ""))
        if not job:
            return
        ok, msg = job.add_note(data.get("note"))
        self.send_json({"success": ok, "message": msg or "Not eklendi; bir sonraki planlamada dikkate alınacak."},
                       status=200 if ok else 400)

    def handle_api_ai_answer(self):
        data = self._read_json_payload()
        if data is None:
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return
        job = self._ai_job_or_error(str(data.get("job_id") or ""))
        if not job:
            return
        ok, msg = job.answer(str(data.get("question_id") or ""), str(data.get("answer") or ""))
        self.send_json({"success": ok, "message": msg or "Cevap iletildi."}, status=200 if ok else 400)

    def handle_api_ai_scan_post(self):
        """AI Destekli Dinamik Tarama (POST uç noktası)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        url = (data.get("url") or "").strip()
        modules = data.get("modules") or []
        ai_config = data.get("ai_config") or {}

        if not url:
            self.send_json({"success": False, "error": "URL parametresi eksik."}, status=400)
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.hostname
        except Exception:
            hostname = None

        if not hostname or not ETHICAL_GATE.is_confirmed(hostname):
            self.send_json({
                "success": False,
                "error": "ETIK_ONAY_YOK",
                "message": f"'{hostname or url}' hedefi için AI taraması öncesi etik onay gereklidir."
            }, status=403)
            return

        if data.get("async"):
            # Faz 2: arka plan işi — arayüz /api/ai-status ile canlı olayları ve soruları çeker
            try:
                job = AI_JOBS.start(
                    target=url,
                    runner=lambda job: self._run_ai_pipeline(url, modules, ai_config, job=job),
                    ask_timeout=ai_config.get("ask_timeout") if isinstance(ai_config, dict) else None)
            except JobLimitError as e:
                self.send_json({"success": False, "error": "AI_JOB_LIMIT", "message": str(e)}, status=429)
                return
            self.send_json({"success": True, "job_id": job.id, "status": job.status})
            return

        try:
            result = self._run_ai_pipeline(url, modules, ai_config)
            if not result.get("success"):
                self.send_json(result, status=400)
                return
            self.send_json(result)
        except Exception as e:
            self.send_json({"success": False, "error": f"AI Scan Error: {str(e)}"}, status=500)

    def _run_ai_pipeline(self, url, modules, ai_config, job=None):
        """
        AI Red Team hattı (Strix metodolojisi — doğrulanmış bulgu ilkesi):
        1. Gerçek keşif: crawler + derin başlık + seçili aktif modüller (rate-limited)
        2. Bu gerçek saldırı yüzeyi AI orkestratörüne context olarak verilir
        3. Her LLM hipoteji aynı rate-limited istemciyle CANLI doğrulanır
        4. Analyst yapılandırılmış verdict verir; Reporter yönetici özeti yazar
        """
        thought_chain = []

        def emit(agent, message):
            entry = {"agent": agent, "message": redact_text(str(message))[:500], "ts": int(time.time() * 1000)}
            thought_chain.append(entry)
            if job is not None:
                job.push_event(entry)

        # --- 1. Gerçek keşif / baseline taraması ---
        emit("system", "Aşama 1/3 — Keşif: site haritası, formlar, başlıklar ve temel aktif modüller taranıyor…")
        base_modules = list(dict.fromkeys((modules or []) + ["browser", "deep_headers"]))
        base_modules = [m for m in base_modules if m not in ("ports", "logic")]  # AI hattında gürültü/yavaşlık üreten modüller kapalı
        t0 = time.time()
        real_browser_flag = (_flag(ai_config.get("real_browser")) if isinstance(ai_config, dict) else False) or REAL_BROWSER_DEFAULT
        if real_browser_flag:
            emit("system", "🖥️ Gerçek tarayıcı (headless Chromium) açık: SPA keşfi ve XSS kanıtı kapsam kilitli tarayıcıyla yapılacak.")
        base = run_active_scan(url, base_modules, options={"real_browser": real_browser_flag})
        if not base.get("success"):
            return {"success": False, "error": base.get("error", "BASELINE_TARAMA_HATASI"),
                    "message": base.get("message", "Temel tarama başlatılamadı.")}
        emit("system", "Keşif tamam: %d istek, %d temel bulgu, %d sayfa, %d form." % (
            base.get("requests_sent", 0), len(base.get("findings", [])),
            len(base.get("site_map", [])), len(base.get("forms", []))))

        if job is not None and job.is_cancelled():
            emit("system", "⏹️ İptal edildi; AI aşamasına geçilmedi.")
            return {"success": False, "cancelled": True, "error": "IPTAL_EDILDI",
                    "message": "AI taraması kullanıcı tarafından iptal edildi.", "thought_chain": thought_chain}

        # HTTP başlıkları (AI context'ine eklenecek; HEAD/GET fallback)
        try:
            resp_headers, _status, _final = self.fetch_headers(url)
        except Exception:
            resp_headers = {}

        scan_state = export_scan_state(
            url,
            base.get("site_map", []),
            base.get("findings", []),
            forms=base.get("forms", []),
            headers=resp_headers,
            tech=[t for t in ((base.get("modules") or {}).get("browser") or {}).get("technologies", [])]
        )

        # --- 2+3. Orkestrasyon (tüm AI testleri TEK paylaşımlı rate-limited istemciyle) ---
        emit("system", "Aşama 2/3 — AI ajanları (Scout → Strategist → Analyst) gerçek keşif verisiyle çalışıyor…")
        try:
            orchestrator = AIOrchestrator(ai_config)
        except ValueError as e:
            return {"success": False, "error": "AI_YAPILANDIRMA", "message": str(e)}

        # AI probları: yalnızca etik onaylı hedefin kökenine (scheme + host + port) ve en fazla
        # max_loops × max_tests_per_loop isteğe izin veren ayrı, kapsam kilitli istemci (safety_guard).
        ai_budget = max(1, int(getattr(orchestrator, "max_loops", 3)) * int(getattr(orchestrator, "max_tests_per_loop", 4)))
        ai_client = RateLimitedClient(scope_url=url, max_requests=ai_budget)

        def active_test_callback(test_url, param, payload):
            return run_custom_test(ai_client, test_url, param, payload)

        ai_result = orchestrator.orchestrate_scan(
            target_url=url,
            initial_data=scan_state,
            active_scanner_callback=active_test_callback,
            progress_callback=emit,
            control=job
        )

        # --- 4. Birleştirilmiş yanıt ---
        findings = ai_result.get("verified_findings", [])
        summary = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0, "BİLGİ": 0}
        for f in findings:
            summary[f.get("severity", "ORTA")] = summary.get(f.get("severity", "ORTA"), 0) + 1

        emit("system", "Aşama 3/3 — Tamamlandı: %d tur, %d AI testi, %d doğrulanmış bulgu (%d istek)." % (
            ai_result.get("loops", 0), ai_result.get("tests_executed", 0), len(findings), ai_client.request_count))

        result = {
            "success": True,
            "cancelled": bool(ai_result.get("cancelled")),
            "job_id": job.id if job is not None else None,
            "ai_report": ai_result,
            "thought_chain": thought_chain,
            "findings": findings,
            "summary": summary,
            "narrative_report": ai_result.get("narrative_report", ""),
            "requests_sent": base.get("requests_sent", 0) + ai_client.request_count,
            "duration_ms": int((time.time() - t0) * 1000),
            "rate_limit_seconds": RATE_LIMIT_SECONDS,
            "modules": {
                "recon": {"ran": True, "findings": len(base.get("findings", []))},
                "ai_orchestrator": {"ran": True, "findings": len(findings)}
            },
            "baseline_findings": base.get("findings", []),
            "real_browser": base.get("real_browser"),
            "site_map": base.get("site_map", []),
            "chains": base.get("chains", []),
            "errors": ai_result.get("errors", []),
            "disclaimer": "AI bulguları yalnızca kanıtı HTTP yanıtıyla doğrulanmış zafiyetlerdir; spekülatif bulgu yayınlanmaz."
        }
        ai_threat = _flag((ai_config or {}).get("threat_intel")) if isinstance(ai_config, dict) else False
        self._post_scan_enrichment(result, url, "ai", ai_threat or THREAT_INTEL_DEFAULT, emit=emit)
        return result

    def handle_api_strix_update(self):
        """Strix CLI'yı günceller (--update)."""
        result = STRIX_MANAGER.update_strix()
        self.send_json(result, status=200 if result.get("success") else 400)

    def handle_api_strix_scan_post(self):
        """Strix otonom pentest taramasını başlatır."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return

        url = (data.get("url") or "").strip()
        mode = (data.get("mode") or "standard").strip().lower()
        instruction = (data.get("instruction") or "").strip()[:8000]
        fail_on = (data.get("fail_on") or None)
        extra_targets = data.get("extra_targets") or []
        # --- Tam özellik paritesi: Strix CLI bayrakları ---
        resume = (data.get("resume") or "").strip()[:200]
        scope_mode = (data.get("scope_mode") or None)
        diff_base = (data.get("diff_base") or None)
        config = data.get("config") if isinstance(data.get("config"), dict) else None
        mcp_config = data.get("mcp_config") if isinstance(data.get("mcp_config"), dict) else None
        mcp_servers = data.get("mcp_servers") or []
        mcp_exclude = data.get("mcp_exclude") or []
        target_list = data.get("target_list") or []
        workspace_files = data.get("workspace_files") or []
        ai_config = data.get("ai_config") or {}
        strix_env_opts = data.get("strix_env_opts") if isinstance(data.get("strix_env_opts"), dict) else {}
        try:
            max_turns = int(data.get("max_turns") or 120)
        except (TypeError, ValueError):
            max_turns = 120
        try:
            max_budget = float(data.get("max_budget")) if data.get("max_budget") else None
        except (TypeError, ValueError):
            max_budget = None

        if not url and not resume:
            self.send_json({"success": False, "error": "url alanı gereklidir (veya resume için run adı)"}, status=400)
            return
        if url and not url.startswith(("http://", "https://", "postman://", "./", "../", "/", "~/")) and not url.startswith("git@"):
            url = "https://" + url

        try:
            hostname = urllib.parse.urlparse(url).hostname if (url and url.startswith(("http://", "https://"))) else None
        except ValueError:
            hostname = None
        # Resume: hedef URL yoksa orijinal taramanın hedefinden hostname çöz —
        # etik onay geçidi resume yolunda da zorlanır (sunucu restart sonrası boşluk)
        if not hostname and resume:
            info = STRIX_MANAGER.get_run_info(resume)
            if info and info.get("target"):
                try:
                    hostname = urllib.parse.urlparse(info["target"]).hostname
                except ValueError:
                    hostname = None
        if hostname and not ETHICAL_GATE.is_confirmed(hostname):
            self.send_json({
                "success": False,
                "error": "ETIK_ONAY_YOK",
                "message": "Strix pentest öncesi etik onay gereklidir. Lütfen onay diyaloğunu kabul edin."
            }, status=403)
            return

        result = STRIX_MANAGER.start(url, ai_config, mode=mode,
                                     instruction=instruction, max_turns=max_turns,
                                     max_budget=max_budget,
                                     fail_on=fail_on, extra_targets=extra_targets,
                                     scope_mode=scope_mode, diff_base=diff_base,
                                     config=config, mcp_config=mcp_config,
                                     mcp_servers=mcp_servers, mcp_exclude=mcp_exclude,
                                     target_list=target_list,
                                     workspace_files=workspace_files, resume=resume,
                                     strix_env_opts=strix_env_opts)
        self.send_json(result, status=200 if result.get("success") else 400)

    def handle_api_strix_status(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        scan_id = (qs.get("scan_id") or [""])[0].strip()
        scan = STRIX_MANAGER.get(scan_id)
        if not scan:
            self.send_json({"success": False, "error": "Tarama bulunamadı: %s" % scan_id}, status=404)
            return
        self.send_json(scan.status())

    def handle_api_strix_report(self, parsed_path):
        qs = urllib.parse.parse_qs(parsed_path.query)
        scan_id = (qs.get("scan_id") or [""])[0].strip()
        run_name = (qs.get("run_name") or [""])[0].strip()
        if run_name:
            rep = STRIX_MANAGER.get_report_by_run_name(run_name)
            if not rep:
                self.send_json({"success": False, "error": "Geçmiş tarama bulunamadı: %s" % run_name}, status=404)
                return
            self.send_json(rep)
            return
        scan = STRIX_MANAGER.get(scan_id)
        if not scan:
            self.send_json({"success": False, "error": "Tarama bulunamadı: %s" % scan_id}, status=404)
            return
        self.send_json(scan.report())

    def handle_api_strix_cancel(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"success": False, "error": "Geçersiz JSON gövdesi"}, status=400)
            return
        scan_id = (data.get("scan_id") or "").strip()
        scan = STRIX_MANAGER.get(scan_id)
        if not scan:
            self.send_json({"success": False, "error": "Tarama bulunamadı"}, status=404)
            return
        self.send_json(scan.cancel())

    def fetch_headers(self, url):
        # Güvenlik & Pasiflik: Yalnızca başlıkları al, gövdeyi indirme
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
            },
            method="HEAD"
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return headers, resp.status, resp.geturl()
        except urllib.error.HTTPError as e:
            # Bazı sunucular HEAD metodunu 405 ile reddeder; bu durumda GET deneriz
            if e.code in (405, 501):
                req.method = "GET"
                with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    return headers, resp.status, resp.geturl()
            raise

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Temiz terminal çıktısı (yalnızca önemli olaylar)
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} - {format % args}\n")

def find_available_port(host=HOST, start_port=DEFAULT_PORT, max_attempts=10):
    import socket
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                return port
            except OSError:
                continue
    return None

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        restored = updater.restore_persisted_update(APP_DIR)
        if restored:
            print(f" [Updater] Kalıcı birimden {restored} güncel dosya geri yüklendi.", flush=True)
    except Exception:
        pass

    port = find_available_port(HOST, DEFAULT_PORT)
    if not port:
        print(f"HATA: {DEFAULT_PORT}-{DEFAULT_PORT+10} aralığında boş port bulunamadı.", file=sys.stderr)
        sys.exit(1)

    server = ThreadingHTTPServer((HOST, port), ScannerHTTPHandler)
    display_host = "127.0.0.1" if HOST in ("0.0.0.0", "") else HOST
    url = f"http://{display_host}:{port}"

    print("=" * 65)
    print(" 🛡️  Web Security Scanner — Yerel & Docker Sunucu (Local Mode)")
    print("=" * 65)
    print(f" • Adres:          {url}")
    print(f" • Dinlenen Ağ:    {HOST}:{port}")
    print(f" • Başlık API:     {url}/api/headers?url=https://example.com")
    try:
        pruned_scans = scan_history.prune() if scan_history.history_enabled() else 0
    except Exception:
        pruned_scans = 0
    if scan_history.history_enabled():
        pruned_note = (", %d eski kayıt silindi" % pruned_scans) if pruned_scans else ""
        print(" • Tarama geçmişi: %s (%d gün saklanır%s)" % (scan_history.db_path(), scan_history.retention_days(), pruned_note))
    else:
        print(" • Tarama geçmişi: kapalı (WSS_HISTORY=0)")
    print(" • Tehdit istihbaratı: " + ("varsayılan AÇIK (WSS_THREAT_INTEL=1)" if THREAT_INTEL_DEFAULT
                                     else "varsayılan kapalı (tarama başına açılır)"))
    try:
        browser_caps = headless_browser.capabilities()
    except Exception as e:
        browser_caps = {"available": False, "reason": str(e)}
    if browser_caps.get("available"):
        print(" • Gerçek tarayıcı: %s %s (sandbox: %s%s) — tarama başına açılır" % (
            browser_caps.get("binary", "chromium"), browser_caps.get("version", ""), browser_caps.get("sandbox", "-"),
            ", yalıtılmış yan konteyner" if browser_caps.get("remote") else ""))
    else:
        print(" • Gerçek tarayıcı: kullanılamıyor — %s" % str(browser_caps.get("reason") or "")[:140])
    print(f" • Sağlık:         {url}/healthz")
    if API_TOKEN_FROM_ENV:
        print(" • API anahtarı:   WSS_API_TOKEN ortam değişkeninden alındı")
    else:
        print(f" • API anahtarı:   {API_TOKEN}")
    print("                   (curl/CI: -H 'X-WSS-Token: <anahtar>' — arayüz anahtarı otomatik kullanır)")
    print("=" * 65)

    should_open_browser = (
        not NO_BROWSER and
        "--no-browser" not in sys.argv and
        HOST not in ("0.0.0.0",) and
        not os.path.exists("/.dockerenv")
    )

    if should_open_browser:
        print(" Tarayıcınız açılıyor... Kapatmak için Ctrl+C tuşlarına basın.\n")
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    else:
        print(" Tarayıcı açma atlandı (Headless / Docker modu). Sunucu hazır.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu durduruldu. Güvenli günler!")
        server.server_close()

if __name__ == "__main__":
    main()
