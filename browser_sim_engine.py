#!/usr/bin/env python3
"""
Web Security Scanner — Tarayıcı Simülasyon Motoru (Faz 6E)
Saf Python stdlib ile tarayıcı-benzeri keşif ve istismar testleri:
1. Sayfa Gezgini (Crawler): link takibi + form keşfi (derinlik/sayfa limitli)
2. JS Dosya Analizi: harici .js indirip DOM sink ↔ kaynak eşleştirme (DOM XSS kanıtı)
3. Form Keşfi + Otomatik Enjeksiyon: formlardaki input'lara zararsız payload'lar
4. Clickjacking Testi: iframe'e gömülebilirlik kontrolü
5. Oturum Akışı Analizi: login sonrası çerez değişimi / token rotasyonu

Etik onay + rate limit (active_scan_engine altyapısını kullanır).
Yalnızca Python 3 standart kütüphanesi.
"""

import os
import re
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser

# Crawler limitleri (hedefi yormamak için)
CRAWL_MAX_PAGES = 10          # tarama başına maksimum sayfa
CRAWL_MAX_DEPTH = 2           # başlangıç sayfasından maksimum derinlik
CRAWL_MAX_JS_FILES = 5        # analiz edilecek maksimum harici JS dosyası

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 WebSecurityScanner/1.0"

# Zararsız test payload'ları (form enjeksiyonu için — active_scan_engine ile tutarlı)
FORM_PAYLOADS = {
    "sqli": "'",                       # error-based tek tırnak
    "xss": "wzxqmk731",                # yansıma marker'ı (zararsız dize)
    "ssti": "{{7*7}}",                 # şablon motoru marker'ı
}

SQL_ERROR_SIGNATURES = re.compile(
    r"you have an error in your sql syntax|warning[:;]\s*mysql|unclosed quotation mark|"
    r"quoted string not properly terminated|ora-\d{5}|sqlite3?\.(?:operational|programming)error",
    re.IGNORECASE
)


# =============================================================
# HTML Ayrıştırıcı (form + link keşfi — stdlib HTMLParser)
# =============================================================
class PageParser(HTMLParser):
    """Sayfadan linkleri, formları ve form alanlarını çıkarır."""

    def __init__(self):
        super().__init__()
        self.links = []          # href değerleri
        self.scripts = []        # script src değerleri
        self.forms = []          # form sözlükleri
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
                "token_field_found": False
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = a.get("name", "")
            if not name:
                return
            itype = (a.get("type") or "text").lower()
            # CSRF token alanı mı?
            if re.search(r"csrf|_token|authenticity", name, re.IGNORECASE):
                self._current_form["token_field_found"] = True
            # hidden alanların değeri korunur (token'ler submit'te gerekebilir)
            self._current_form["inputs"].append({
                "name": name,
                "type": itype,
                "value": a.get("value", "")
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def parse_page(html):
    """HTML'i ayrıştırıp link, script ve form bilgilerini döndürür."""
    parser = PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass  # bozuk HTML'de bile toplananlar korunur
    if parser._current_form is not None:  # kapanmamış form
        parser.forms.append(parser._current_form)
    return parser


# =============================================================
# 1. SAYFA GEZGİNİ (CRAWLER)
# =============================================================
def crawl_site(start_url, client):
    """Rate-limited crawler: linkleri takip eder, formları ve JS dosyalarını toplar.

    Dönüş: {
      "pages": [{url, status, forms, links_found, depth}],
      "all_forms": [...], "js_files": [...], "errors": [...]
    }
    """
    visited = set()
    queue = [(start_url, 0)]
    pages = []
    all_forms = []
    js_files = []
    errors = []

    origin = urllib.parse.urlparse(start_url)
    base_domain = origin.netloc

    def normalize(url, current_url):
        """Göreli URL'yi mutlak URL'e çevirir; aynı domain + http(s) filtresi."""
        try:
            abs_url = urllib.parse.urljoin(current_url, url)
        except ValueError:
            return None
        p = urllib.parse.urlparse(abs_url)
        if p.scheme not in ("http", "https"):
            return None
        if p.netloc != base_domain:
            return None  # dış domain: taranmaz (yalnızca href olarak kaydedilir)
        return abs_url.split("#")[0]  # fragment temizle

    while queue and len(visited) < CRAWL_MAX_PAGES:
        url, depth = queue.pop(0)
        if url in visited or depth > CRAWL_MAX_DEPTH:
            continue
        visited.add(url)

        resp = _safe_get(client, url)
        if resp.get("error"):
            errors.append({"url": url, "error": resp["error"]})
            pages.append({"url": url, "status": None, "forms": 0, "links_found": 0, "depth": depth, "error": resp["error"]})
            continue

        page_info = parse_page(resp["body"])
        # JS dosyalarını mutlak URL olarak kaydet
        for src in page_info.scripts:
            abs_src = urllib.parse.urljoin(url, src)
            if abs_src not in [j["url"] for j in js_files]:
                js_files.append({"url": abs_src, "found_on": url})

        # Formları sayfa URL'si ile zenginleştir
        for form in page_info.forms:
            action_abs = urllib.parse.urljoin(url, form["action"] or url)
            form["page_url"] = url
            form["action_url"] = action_abs
            all_forms.append(form)

        # Aynı-domain linkleri kuyruğa ekle
        new_links = 0
        for href in page_info.links:
            norm = normalize(href, url)
            if norm and norm not in visited:
                queue.append((norm, depth + 1))
                new_links += 1

        pages.append({
            "url": url, "status": resp["status"], "forms": len(page_info.forms),
            "links_found": new_links, "depth": depth
        })

    return {
        "pages": pages,
        "all_forms": all_forms,
        "js_files": js_files[:CRAWL_MAX_JS_FILES * 3],  # ham liste (analizde ilk N alınır)
        "errors": errors,
        "pages_visited": len(visited)
    }


# =============================================================
# 2. JS DOSYA ANALİZİ (DOM XSS KANITI)
# =============================================================
JS_DOM_SINKS = re.compile(
    r"(?:document\.write(?:ln)?\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|"
    r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'])"
)
JS_DOM_SOURCES = re.compile(
    r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|referrer|cookie)|window\.name|"
    r"URLSearchParams|localStorage\.getItem|sessionStorage\.getItem|document\.getElementById\([^)]*\)\.value)"
)


def analyze_js_files(js_files, client):
    """Harici JS dosyalarını indirir ve DOM XSS (kaynak→sink) analizi yapar."""
    findings = []
    analyzed = 0

    for js_info in js_files[:CRAWL_MAX_JS_FILES]:
        resp = _safe_get(client, js_info["url"])
        if resp.get("error") or not resp.get("body"):
            continue
        analyzed += 1
        body = resp["body"]
        lines = body.split("\n")

        # Satır bazlı kaynak→sink eşleştirme + değişken taint (JS taint motoru yaklaşımı)
        tainted_vars = {}
        assign_rx = re.compile(r'(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?);')
        for line in lines:
            for m in assign_rx.finditer(line):
                if JS_DOM_SOURCES.search(m.group(2)):
                    tainted_vars[m.group(1)] = True

        for lineno, line in enumerate(lines, 1):
            sink_m = JS_DOM_SINKS.search(line)
            if not sink_m:
                continue
            region = line[max(0, sink_m.start() - 40):sink_m.start() + 140]
            src_hit = JS_DOM_SOURCES.search(region) or JS_DOM_SOURCES.search(line)
            tainted_hit = any(re.search(r'\b' + re.escape(v) + r'\b', region) for v in tainted_vars)

            if src_hit or tainted_hit:
                findings.append({
                    "test": "DOM XSS (JS Analizi)", "severity": "YÜKSEK",
                    "title": "Harici JS dosyasında DOM XSS akışı (%s)" % _basename(js_info["url"]),
                    "evidence": "Satır %d: %s ... [kaynak: %s]" % (lineno, _clean(region), src_hit.group(0)[:40] if src_hit else "tainted değişken"),
                    "cwe": "CWE-79",
                    "fix": "Konum kaynaklarını DOM'a yazmadan önce sterilize edin (DOMPurify); sink'ten kaçının."
                })
                break  # dosya başına 1 kanıt yeterli

    return findings, {"js_analyzed": analyzed, "js_total": len(js_files)}


# =============================================================
# 3. FORM ENJEKSİYONU (ZARARSIZ PAYLOAD'LAR)
# =============================================================
def inject_forms(forms, client):
    """Keşfedilen formlara zararsız payload'lar gönderir (GET formları; POST denemesi yapılır)."""
    findings = []
    tested = 0
    tested_actions = set()  # aynı form action'ı birden çok sayfada tekrar test edilmesin

    for form in forms[:8]:  # en fazla 8 forma bak (tekrarlar elenir)
        action_url = form["action_url"]
        if action_url in tested_actions:
            continue
        tested_actions.add(action_url)

        text_inputs = [i for i in form["inputs"] if i["type"] in ("text", "search", "url", "email", "")]
        if not text_inputs:
            continue

        for payload_type, payload in FORM_PAYLOADS.items():
            tested += 1
            # Form parametrelerini kur: text input'lara payload, diğerlerine mevcut değer
            params = {}
            for inp in form["inputs"]:
                params[inp["name"]] = inp["value"]
            target_input = text_inputs[0]  # ilk metin alanı
            params[target_input["name"]] = payload

            if form["method"] == "GET":
                resp = _safe_get(client, action_url, params=params)
            else:
                # POST denemesi: urllib ile form-encoded gövde
                resp = _post_form(client, action_url, params)

            if resp.get("error"):
                continue
            body = resp.get("body", "")

            # SQLi error-based kontrolü
            if payload_type == "sqli" and SQL_ERROR_SIGNATURES.search(body):
                m = SQL_ERROR_SIGNATURES.search(body)
                findings.append({
                    "test": "Form SQL Injection", "severity": "KRİTİK",
                    "title": "Form girdisinde error-based SQLi (%s → %s)" % (form["page_url"][:50], target_input["name"]),
                    "evidence": "Payload: %r → hata imzası: %s" % (payload, _clean(m.group(0))),
                    "cwe": "CWE-89",
                    "fix": "Form girdilerini parametreli sorgularla işleyin."
                })
                break  # form için bir kanıt yeter

            # XSS yansıma kontrolü
            if payload_type == "xss" and payload in body:
                idx = body.find(payload)
                ctx = body[max(0, idx - 40):idx + 60]
                findings.append({
                    "test": "Form XSS", "severity": "YÜKSEK",
                    "title": "Form girdisinde encode edilmemiş yansıma (%s → %s)" % (form["page_url"][:50], target_input["name"]),
                    "evidence": "Marker %r ham olarak yansıdı: ...%s..." % (payload, _clean(ctx)),
                    "cwe": "CWE-79",
                    "fix": "Form çıktısını bağlama göre kodlayın (textContent/escape)."
                })
                break

            # SSTI kontrolü
            if payload_type == "ssti" and "49" in body and "{{7*7}}" not in body:
                findings.append({
                    "test": "Form SSTI", "severity": "KRİTİK",
                    "title": "Form girdisinde şablon motoru değerlendirmesi (%s → %s)" % (form["page_url"][:50], target_input["name"]),
                    "evidence": "{{7*7}} gönderildi, yanıt 49 içeriyor (payload ham dönmedi).",
                    "cwe": "CWE-1336",
                    "fix": "Kullanıcı girdisini şablon olarak değerlendirmeyin."
                })
                break

        # CSRF notu: token'sız form bilgisi (danışma)
        if not form.get("token_field_found"):
            findings.append({
                "test": "Form CSRF", "severity": "DÜŞÜK",
                "title": "Token'sız form (%s)" % form["page_url"][:60],
                "evidence": "Form action: %s — CSRF token alanı tespit edilmedi." % form["action_url"][:60],
                "cwe": "CWE-352",
                "fix": "Forma CSRF token ekleyin."
            })

    return findings, {"forms_tested": len(tested_actions), "requests_made": tested}


def _post_form(client, url, params):
    """Form-encoded POST isteği gönderir (rate-limit sayaçlarına dahil)."""
    if client.request_count >= 60:
        return {"error": "istek limiti"}
    elapsed = time.time() - client.last_request_at
    if elapsed < 1.5:
        time.sleep(1.5 - elapsed)

    data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded"
    }, method="POST")
    client.request_count += 1
    client.last_request_at = time.time()
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"status": resp.status, "body": resp.read(256 * 1024).decode("utf-8", errors="replace"), "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(256 * 1024).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body, "error": None}
    except Exception as e:
        return {"error": str(e)}


# =============================================================
# 4. CLICKJACKING TESTİ
# =============================================================
def test_clickjacking(base_url, client):
    """Sayfanın iframe'e gömülebilirliğini kontrol eder (X-Frame-Options / CSP frame-ancestors)."""
    resp = _safe_get(client, base_url)
    findings = []
    if resp.get("error"):
        return findings

    headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    frame_ancestors = re.search(r"frame-ancestors\s+([^;]+)", csp)

    protected = False
    if xfo.upper() in ("DENY", "SAMEORIGIN"):
        protected = True
    if frame_ancestors and frame_ancestors.group(1).strip() not in ("*", "'self'", "'none'"):
        pass  # kısıtlı liste = kısmi koruma
    if frame_ancestors and frame_ancestors.group(1).strip() == "'none'":
        protected = True

    if not protected and not xfo:
        findings.append({
            "test": "Clickjacking", "severity": "ORTA",
            "title": "Sayfa iframe'e gömülebilir (clickjacking riski)",
            "evidence": "X-Frame-Options başlığı yok; CSP frame-ancestors tanımlı değil.",
            "cwe": "CWE-1021",
            "fix": "X-Frame-Options: DENY veya CSP frame-ancestors 'self' ekleyin."
        })
    elif not protected:
        findings.append({
            "test": "Clickjacking", "severity": "DÜŞÜK",
            "title": "Kısmi clickjacking koruması",
            "evidence": "X-Frame-Options: %s (zayıf değer); frame-ancestors: %s" % (xfo or "yok", frame_ancestors.group(1) if frame_ancestors else "yok"),
            "cwe": "CWE-1021",
            "fix": "X-Frame-Options: DENY kullanın."
        })
    return findings


# =============================================================
# 5. OTURUM AKIŞI ANALİZİ
# =============================================================
def analyze_session_flow(base_url, client):
    """Art arda isteklerle çerez değişimi ve oturum kalıcılığı analiz eder."""
    findings = []

    resp1 = _safe_get(client, base_url)
    if resp1.get("error"):
        return findings

    cookies1 = _extract_cookies(resp1.get("headers") or {})

    # İkinci istek: oturum kalıcılığı
    resp2 = _safe_get(client, base_url)
    if resp2.get("error"):
        return findings
    cookies2 = _extract_cookies(resp2.get("headers") or {})

    # Çerez güvenlik bayrakları (Set-Cookie başlıklarından)
    set_cookie_headers = _get_set_cookies(resp1.get("headers") or {})
    for cookie_raw in set_cookie_headers:
        attrs_lower = cookie_raw.lower()
        name = cookie_raw.split("=")[0].strip()
        issues = []
        if "httponly" not in attrs_lower:
            issues.append("HttpOnly yok")
        if "secure" not in attrs_lower:
            issues.append("Secure yok")
        if "samesite" not in attrs_lower:
            issues.append("SameSite yok")
        if issues and re.search(r"sess|auth|token|login|sid", name, re.IGNORECASE):
            findings.append({
                "test": "Oturum Akışı", "severity": "ORTA",
                "title": "Oturum çerezinde eksik güvenlik bayrakları (%s)" % name,
                "evidence": "Set-Cookie: %s ... → %s" % (cookie_raw[:60], ", ".join(issues)),
                "cwe": "CWE-1004",
                "fix": "Oturum çerezlerine HttpOnly; Secure; SameSite=Lax ekleyin."
            })

    # Oturum kimliği değişimi kontrolü (ilk istek vs ikinci)
    session_names_1 = {c for c in cookies1 if re.search(r"sess|sid|csrf", c, re.IGNORECASE)}
    session_names_2 = {c for c in cookies2 if re.search(r"sess|sid|csrf", c, re.IGNORECASE)}
    if session_names_1 and session_names_1 != session_names_2:
        findings.append({
            "test": "Oturum Akışı", "severity": "BİLGİ",
            "title": "İstekler arasında oturum kimliği değişimi algılandı",
            "evidence": "1. istek: %s / 2. istek: %s — CSRF token rotasyonu olabilir (iyi pratik) veya tutarsız oturum." % (
                sorted(session_names_1)[:3], sorted(session_names_2)[:3]),
            "cwe": "-",
            "fix": "Değişim bilinçli değilse oturum yönetimini gözden geçirin."
        })

    return findings, {"cookies_seen": sorted(set(list(cookies1) + list(cookies2)))}


def _get_set_cookies(headers):
    """Tüm Set-Cookie başlıklarını listeler (dict normalizasyonu kayıplarını önler)."""
    result = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            result.append(v)
    return result

def _extract_cookies(headers):
    """Set-Cookie başlıklarından çerez adlarını çıkarır."""
    names = {}
    for raw in _get_set_cookies(headers):
        name = raw.split("=")[0].strip()
        names[name] = True
    return names


# =============================================================
# Yardımcılar
# =============================================================
def _safe_get(client, url, **kwargs):
    """Rate limit doldugunda (StopIteration) taramayi kilitlemeden zarif durdurur."""
    try:
        return client.get(url, **kwargs)
    except StopIteration:
        return {"error": "istek limiti"}

def _basename(url):
    return url.split("/")[-1].split("?")[0][:40] or "(root)"

def _clean(s):
    return s.replace("\n", " ").strip()[:140]


# =============================================================
# Ana Orkestratör: Tarayıcı Simülasyonu Taraması
# =============================================================
def run_browser_simulation(base_url, client, ethical_gate_check=True):
    """Tarayıcı simülasyon taramasını orkestre eder (etik onay üst katmanda zorunlu)."""
    start = time.time()
    findings = []
    stats = {}

    # 1. Crawl
    crawl_result = crawl_site(base_url, client)
    stats["crawl"] = {
        "pages_visited": crawl_result["pages_visited"],
        "forms_found": len(crawl_result["all_forms"]),
        "js_files_found": len(crawl_result["js_files"]),
        "errors": len(crawl_result["errors"])
    }

    # Crawl haritası bilgilendirmesi
    findings.append({
        "test": "Site Haritası", "severity": "BİLGİ",
        "title": "Keşif tamamlandı: %d sayfa, %d form, %d JS dosyası" % (
            crawl_result["pages_visited"], len(crawl_result["all_forms"]), len(crawl_result["js_files"])),
        "evidence": "Ziyaret edilen: " + ", ".join(p["url"][:60] for p in crawl_result["pages"][:5]),
        "cwe": "-", "fix": "-"
    })

    # 2. JS dosya analizi
    js_findings, js_stats = analyze_js_files(crawl_result["js_files"], client)
    findings += js_findings
    stats["js_analysis"] = js_stats

    # 3. Form enjeksiyonu
    form_findings, form_stats = inject_forms(crawl_result["all_forms"], client)
    findings += form_findings
    stats["form_injection"] = form_stats

    # 4. Clickjacking
    findings += test_clickjacking(base_url, client)

    # 5. Oturum akışı
    session_result = analyze_session_flow(base_url, client)
    if isinstance(session_result, tuple):
        findings += session_result[0]
        stats["session"] = session_result[1]
    else:
        findings += session_result

    summary = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0, "BİLGİ": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {
        "success": True,
        "url": base_url,
        "modules": {
            "crawler": {"ran": True, "pages": crawl_result["pages_visited"]},
            "js_analysis": {"ran": js_stats["js_analyzed"] > 0 or js_stats["js_total"] == 0, **js_stats},
            "form_injection": {"ran": True, **form_stats},
            "clickjacking": {"ran": True},
            "session_flow": {"ran": True}
        },
        "stats": stats,
        "summary": summary,
        "findings": findings,
        "site_map": crawl_result["pages"],
        "requests_sent": client.request_count,
        "duration_ms": int((time.time() - start) * 1000),
        "disclaimer": "Tarayıcı simülasyonu rate-limited ve zararsız payload'larla yürütülmüştür."
    }
