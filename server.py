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
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser
import threading
import time

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 WebSecurityScanner/1.0"
TIMEOUT_SECONDS = 8

class ScannerHTTPHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Yerel istemci için CORS başlıkları (aynı makine içinde sorunsuz çalışma)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        # 1. API: /api/headers?url=...
        if parsed.path == "/api/headers":
            self.handle_api_headers(parsed)
            return

        # 1b. API: /api/deep-scan?url=... (Derin Pasif Tarama - Faz 1)
        if parsed.path == "/api/deep-scan":
            self.handle_api_deep_scan(parsed)
            return

        # 2. API: /api/status (sunucu aktif mi kontrolü)
        if parsed.path == "/api/status":
            self.send_json({
                "status": "online",
                "mode": "local_server",
                "version": "1.0.0",
                "host": HOST
            })
            return

        # 3. Statik dosya sunumu (index.html, css/, js/)
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

            # 1.2 TLS / Sertifika Analizi (yalnızca HTTPS hedeflerde)
            if is_https:
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=TIMEOUT_SECONDS) as sock:
                        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                            cert = tls_sock.getpeercert()
                            tls_version = tls_sock.version()

                    import datetime
                    not_after = cert.get("notAfter", "")
                    expiry_days = None
                    if not_after:
                        try:
                            exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                            expiry_days = (exp_date - datetime.datetime.now(datetime.timezone.utc)).days
                        except Exception:
                            pass

                    tls_findings = []
                    if expiry_days is not None and expiry_days < 30:
                        tls_findings.append({"level": "YÜKSEK" if expiry_days < 7 else "ORTA", "issue": f"Sertifika {expiry_days} gün içinde sona eriyor", "evidence": not_after})
                    if tls_version and tls_version in ("TLSv1", "TLSv1.1"):
                        tls_findings.append({"level": "YÜKSEK", "issue": f"Eski TLS protokolü: {tls_version}", "evidence": "TLS 1.0/1.1 kullanımdan kaldırıldı"})

                    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"] if cert else []
                    if hostname not in sans:
                        tls_findings.append({"level": "ORTA", "issue": "Hostname SAN listesinde birebir eşleşmiyor (wildcard olabilir)", "evidence": ", ".join(sans[:5])})

                    result["tls"] = {
                        "analyzed": True,
                        "protocol": tls_version,
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
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Temiz terminal çıktısı (yalnızca önemli olaylar)
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} - {format % args}\n")

def find_available_port(start_port=DEFAULT_PORT, max_attempts=10):
    import socket
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, port))
                return port
            except OSError:
                continue
    return None

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    port = find_available_port(DEFAULT_PORT)
    if not port:
        print(f"HATA: {DEFAULT_PORT}-{DEFAULT_PORT+10} aralığında boş port bulunamadı.", file=sys.stderr)
        sys.exit(1)

    server = HTTPServer((HOST, port), ScannerHTTPHandler)
    url = f"http://{HOST}:{port}"

    print("=" * 65)
    print(" 🛡️  Web Security Scanner — Yerel Sunucu (Local Mode)")
    print("=" * 65)
    print(f" • Adres:          {url}")
    print(f" • Dinlenen IP:    {HOST} (Yalnızca yerel cihaz — dışarıya kapalı)")
    print(f" • Başlık API:     {url}/api/headers?url=https://example.com")
    print(f" • Durum:          {url}/api/status")
    print("=" * 65)
    print(" Tarayıcınız açılıyor... Kapatmak için Ctrl+C tuşlarına basın.\n")

    # Tarayıcıyı otomatik açma (isteğe bağlı bayrak --no-browser ile kapatılabilir)
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu durduruldu. Güvenli günler!")
        server.server_close()

if __name__ == "__main__":
    main()
