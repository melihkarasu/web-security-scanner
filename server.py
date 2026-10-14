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

# Faz 3: Aktif tarama motoru (etik onay geçidi + rate limiter içerir)
from active_scan_engine import ETHICAL_GATE, run_active_scan, run_custom_test, export_scan_state, RateLimitedClient, RATE_LIMIT_SECONDS
from ai_orchestrator import AIOrchestrator
from ai_connector import AIProviderFactory
from strix_engine import STRIX_MANAGER, strix_capabilities

HOST = os.environ.get("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("PORT", "8765"))
NO_BROWSER = os.environ.get("NO_BROWSER", "0").lower() in ("1", "true", "yes")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 WebSecurityScanner/1.0"
TIMEOUT_SECONDS = 8

class ScannerHTTPHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Yerel istemci ve konteyner için CORS başlıkları
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

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

        self.send_json({"success": False, "error": "Bilinmeyen POST ucu"}, status=404)

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

        # 1c. API: /api/sast?path=... (Kaynak Kod Analizi - Faz 2)
        if parsed.path == "/api/sast":
            self.handle_api_sast(parsed)
            return

        # 1d. API: /api/active-scan?url=... (Aktif Güvenlik Testi - Faz 3)
        if parsed.path == "/api/active-scan":
            self.handle_api_active_scan(parsed)
            return

        # 1e. API: /api/ai-scan (GET uyumluluğu)
        if parsed.path == "/api/ai-scan":
            self.handle_api_ai_scan(parsed)
            return

        # 1f. API: /api/strix-capabilities (Strix kurulum + özellik tespiti)
        if parsed.path == "/api/strix-capabilities":
            self.send_json(strix_capabilities())
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

    # =============================================================
    # FAZ 2: SAST — Kaynak Kod Analizi Uç Noktası (/api/sast)
    # Dizin taraması (42 kural) + bağımlılık CVE kontrolü (OSV)
    # =============================================================
    def _resolve_sast_path(self, raw_path):
        expanded = os.path.expanduser(raw_path)
        if os.path.isdir(expanded):
            return os.path.abspath(expanded), []
        stripped = raw_path.strip("/").strip()
        search_roots = ["/www/wwwroot", "/opt", "/root", os.getcwd(), os.path.expanduser("~")]
        if stripped:
            for root in search_roots:
                cand = os.path.join(root, stripped)
                if os.path.isdir(cand):
                    return os.path.abspath(cand), []
        available = []
        for root in ("/www/wwwroot", "/opt"):
            if os.path.isdir(root):
                try:
                    for name in sorted(os.listdir(root))[:15]:
                        full = os.path.join(root, name)
                        if os.path.isdir(full) and not name.startswith("."):
                            available.append(full)
                except OSError:
                    pass
        return None, available

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

        try:
            result = run_active_scan(raw_url, modules)
            if not result.get("success") and result.get("error") == "ETIK_ONAY_YOK":
                self.send_json({
                    "success": False,
                    "error": "ETIK_ONAY_YOK",
                    "message": "Aktif test öncesi etik onay gereklidir. Lütfen onay diyaloğunu kabul edin."
                }, status=403)
                return
            self.send_json(result)
        except Exception as e:
            self.send_json({"success": False, "error": "Aktif tarama başarısız: %s" % str(e)}, status=500)

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

        try:
            result = self._run_ai_pipeline(url, modules, ai_config)
            if not result.get("success"):
                self.send_json(result, status=400)
                return
            self.send_json(result)
        except Exception as e:
            self.send_json({"success": False, "error": f"AI Scan Error: {str(e)}"}, status=500)

    def _run_ai_pipeline(self, url, modules, ai_config):
        """
        AI Red Team hattı (Strix metodolojisi — doğrulanmış bulgu ilkesi):
        1. Gerçek keşif: crawler + derin başlık + seçili aktif modüller (rate-limited)
        2. Bu gerçek saldırı yüzeyi AI orkestratörüne context olarak verilir
        3. Her LLM hipoteji aynı rate-limited istemciyle CANLI doğrulanır
        4. Analyst yapılandırılmış verdict verir; Reporter yönetici özeti yazar
        """
        thought_chain = []

        def emit(agent, message):
            thought_chain.append({"agent": agent, "message": str(message)[:500], "ts": int(time.time() * 1000)})

        # --- 1. Gerçek keşif / baseline taraması ---
        emit("system", "Aşama 1/3 — Keşif: site haritası, formlar, başlıklar ve temel aktif modüller taranıyor…")
        base_modules = list(dict.fromkeys((modules or []) + ["browser", "deep_headers"]))
        base_modules = [m for m in base_modules if m not in ("ports", "logic")]  # AI hattında gürültü/yavaşlık üreten modüller kapalı
        t0 = time.time()
        base = run_active_scan(url, base_modules)
        if not base.get("success"):
            return {"success": False, "error": base.get("error", "BASELINE_TARAMA_HATASI"),
                    "message": base.get("message", "Temel tarama başlatılamadı.")}
        emit("system", "Keşif tamam: %d istek, %d temel bulgu, %d sayfa, %d form." % (
            base.get("requests_sent", 0), len(base.get("findings", [])),
            len(base.get("site_map", [])), len(base.get("forms", []))))

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

        ai_client = RateLimitedClient()

        def active_test_callback(test_url, param, payload):
            return run_custom_test(ai_client, test_url, param, payload)

        ai_result = orchestrator.orchestrate_scan(
            target_url=url,
            initial_data=scan_state,
            active_scanner_callback=active_test_callback,
            progress_callback=emit
        )

        # --- 4. Birleştirilmiş yanıt ---
        findings = ai_result.get("verified_findings", [])
        summary = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0, "BİLGİ": 0}
        for f in findings:
            summary[f.get("severity", "ORTA")] = summary.get(f.get("severity", "ORTA"), 0) + 1

        emit("system", "Aşama 3/3 — Tamamlandı: %d tur, %d AI testi, %d doğrulanmış bulgu (%d istek)." % (
            ai_result.get("loops", 0), ai_result.get("tests_executed", 0), len(findings), ai_client.request_count))

        return {
            "success": True,
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
            "site_map": base.get("site_map", []),
            "chains": base.get("chains", []),
            "errors": ai_result.get("errors", []),
            "disclaimer": "AI bulguları yalnızca kanıtı HTTP yanıtıyla doğrulanmış zafiyetlerdir; spekülatif bulgu yayınlanmaz."
        }

    def handle_api_ai_scan(self, parsed_path):
        """
        AI Destekli Dinamik Tarama Uç Noktası (GET uyumluluğu).
        """
        try:
            qs = urllib.parse.parse_qs(parsed_path.query)
            url = (qs.get("url") or [""])[0].strip()
            if not url:
                self.send_json({"success": False, "error": "URL parametresi eksik."}, status=400)
                return

            provider_config = {
                "provider": (qs.get("provider") or ["openai"])[0],
                "model": (qs.get("model") or ["gpt-4o"])[0],
                "base_url": (qs.get("base_url") or ["https://api.openai.com/v1"])[0],
                "project_id": (qs.get("project_id") or [""])[0],
                "region": (qs.get("region") or ["global"])[0],
                "auth": {
                    "type": (qs.get("auth_type") or ["api_key"])[0],
                    "value": (qs.get("auth_value") or [""])[0]
                }
            }

            parsed_url = urllib.parse.urlparse(url)
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
                parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.hostname or not ETHICAL_GATE.is_confirmed(parsed_url.hostname):
                self.send_json({
                    "success": False,
                    "error": "ETIK_ONAY_YOK",
                    "message": "AI taraması öncesi etik onay gereklidir."
                }, status=403)
                return

            # Yeni hat (POST ile aynı): gerçek keşif + doğrulamalı orkestrasyon
            result = self._run_ai_pipeline(url, [], provider_config)
            self.send_json(result, status=200 if result.get("success") else 400)

        except Exception as e:
            self.send_json({"success": False, "error": f"AI Scan Error: {str(e)}"}, status=500)

    # =============================================================
    # STRIX: Gerçek Strix CLI entegrasyonu (subprocess + dosya tabanlı durum)
    # Başlatma etik onay geçidine bağlıdır; durum/rapor uçları salt-okurdur.
    # =============================================================
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

    port = find_available_port(HOST, DEFAULT_PORT)
    if not port:
        print(f"HATA: {DEFAULT_PORT}-{DEFAULT_PORT+10} aralığında boş port bulunamadı.", file=sys.stderr)
        sys.exit(1)

    server = HTTPServer((HOST, port), ScannerHTTPHandler)
    display_host = "127.0.0.1" if HOST in ("0.0.0.0", "") else HOST
    url = f"http://{display_host}:{port}"

    print("=" * 65)
    print(" 🛡️  Web Security Scanner — Yerel & Docker Sunucu (Local Mode)")
    print("=" * 65)
    print(f" • Adres:          {url}")
    print(f" • Dinlenen Ağ:    {HOST}:{port}")
    print(f" • Başlık API:     {url}/api/headers?url=https://example.com")
    print(f" • Durum:          {url}/api/status")
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
