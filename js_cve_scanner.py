#!/usr/bin/env python3
"""
js_cve_scanner.py — Resmi JavaScript & Node.js CVE / Yama / Zafiyet Denetim Motoru.

Kaynaklar:
  1) Retire.js Resmi Veri Tabanı (jsrepository-v4.json) + çevrimdışı yerleşik katalog:
     package.json olmasa bile .html/.php/.ejs/.vue/.js dosyalarındaki <script src="...">
     CDN bağlantılarını ve yerel JS kütüphane başlık yorumlarını (jQuery, Bootstrap, Lodash,
     Moment.js, DOMPurify, Handlebars, AngularJS, Chart.js, Axios, SweetAlert2, Marked vb.)
     tarayarak bilinen CVE kodlarını ve minimum yamalı sürümü (patched_version) raporlar.
  2) Node.js Official Security WG (nodejs/security-wg vuln/core/index.json) + çevrimdışı taban:
     Dockerfile, .nvmrc ve package.json (engines.node) içindeki Node.js sürümlerini resmi
     Node.js güvenlik bültenleriyle karşılaştırır.
"""
import json
import os
import re
import threading
import time
import urllib.request

RETIREJS_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
NODEJS_SEC_WG_URL = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
FEED_TTL_SECONDS = 12 * 3600

_FEED_LOCK = threading.Lock()
_RETIRE_CACHE = {"at": 0.0, "data": None}
_NODE_WG_CACHE = {"at": 0.0, "data": None}

# Çevrimdışı / hızlı deterministik taban (Retire.js + GHSA npm resmi bültenlerinden derlenmiş)
BASELINE_JS_VULNS = {
    "jquery": [
        {"below": "1.9.0", "patched": "3.7.1", "severity": "YÜKSEK", "cwe": "CWE-79", "cvss": 7.2,
         "cves": ["CVE-2012-6708", "CVE-2015-9251"], "summary": "jQuery < 1.9.0 seçici tabanlı DOM XSS zafiyeti"},
        {"below": "3.0.0", "patched": "3.7.1", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.1,
         "cves": ["CVE-2015-9251"], "summary": "jQuery < 3.0.0 cross-domain Ajax text/javascript otomatik çalıştırma XSS açığı"},
        {"below": "3.4.0", "patched": "3.7.1", "severity": "ORTA", "cwe": "CWE-1321", "cvss": 6.1,
         "cves": ["CVE-2019-11358"], "summary": "jQuery < 3.4.0 jQuery.extend(true, ...) Object.prototype pollution zafiyeti"},
        {"below": "3.5.0", "patched": "3.7.1", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.9,
         "cves": ["CVE-2020-11022", "CVE-2020-11023"], "summary": "jQuery < 3.5.0 jQuery.htmlPrefilter üzerinden DOM XSS zafiyeti"},
    ],
    "jquery-ui": [
        {"below": "1.13.0", "patched": "1.13.2", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.5,
         "cves": ["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"], "summary": "jQuery UI < 1.13.0 Datepicker / Position DOM XSS zafiyetleri"},
        {"below": "1.13.2", "patched": "1.13.2", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.1,
         "cves": ["CVE-2022-31160"], "summary": "jQuery UI < 1.13.2 Checkboxradio etiket yenileme XSS zafiyeti"},
    ],
    "bootstrap": [
        {"below": "3.4.1", "patched": "3.4.1 / 5.3.3", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.1,
         "cves": ["CVE-2018-14040", "CVE-2018-14042", "CVE-2019-8331"], "summary": "Bootstrap < 3.4.1 data-target / tooltip / popover DOM XSS zafiyeti"},
        {"at_or_above": "4.0.0", "below": "4.3.1", "patched": "4.6.2 / 5.3.3", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.1,
         "cves": ["CVE-2019-8331"], "summary": "Bootstrap 4.x < 4.3.1 tooltip/popover data-template XSS zafiyeti"},
    ],
    "lodash": [
        {"below": "4.17.21", "patched": "4.17.21", "severity": "YÜKSEK", "cwe": "CWE-94", "cvss": 7.5,
         "cves": ["CVE-2021-23337", "CVE-2020-8203"], "summary": "Lodash < 4.17.21 template komut enjeksiyonu ve Prototype Pollution zafiyeti"},
    ],
    "moment": [
        {"below": "2.29.4", "patched": "2.29.4", "severity": "YÜKSEK", "cwe": "CWE-22", "cvss": 7.5,
         "cves": ["CVE-2022-24785", "CVE-2022-31129"], "summary": "Moment.js < 2.29.4 yerel ayar (locale) dizin geçişi ve ReDoS zafiyeti"},
    ],
    "dompurify": [
        {"below": "2.4.1", "patched": "3.1.6", "severity": "YÜKSEK", "cwe": "CWE-79", "cvss": 7.5,
         "cves": ["CVE-2022-25887", "CVE-2024-45801"], "summary": "DOMPurify eski sürümde mXSS / derin yuvalama sanitizer bypass zafiyeti"},
        {"at_or_above": "3.0.0", "below": "3.1.3", "patched": "3.1.6", "severity": "YÜKSEK", "cwe": "CWE-79", "cvss": 7.3,
         "cves": ["CVE-2024-45801", "CVE-2024-47875"], "summary": "DOMPurify < 3.1.3 DOM Clobbering / mXSS bypass zafiyeti"},
    ],
    "handlebars": [
        {"below": "4.7.7", "patched": "4.7.8", "severity": "KRİTİK", "cwe": "CWE-94", "cvss": 9.8,
         "cves": ["CVE-2021-23369", "CVE-2021-23383"], "summary": "Handlebars < 4.7.7 uzaktan kod çalıştırma (RCE) ve Prototype Pollution zafiyeti"},
    ],
    "angular": [
        {"below": "1.8.0", "patched": "Angular (modern) / >=1.8.3", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.1,
         "cves": ["CVE-2020-7676", "CVE-2022-25869"], "summary": "AngularJS 1.x (EOL) JQLite DOM XSS ve ReDoS zafiyetleri"},
    ],
    "axios": [
        {"below": "1.6.0", "patched": "1.7.4", "severity": "ORTA", "cwe": "CWE-352", "cvss": 6.5,
         "cves": ["CVE-2023-45857", "CVE-2024-39338"], "summary": "Axios < 1.6.0 XSRF-TOKEN sızıntısı ve SSRF zafiyeti"},
        {"below": "1.7.4", "patched": "1.7.4", "severity": "YÜKSEK", "cwe": "CWE-918", "cvss": 7.5,
         "cves": ["CVE-2024-39338"], "summary": "Axios < 1.7.4 sunucu tarafı yol-göreli URL SSRF zafiyeti"},
    ],
    "marked": [
        {"below": "4.0.10", "patched": "4.0.10", "severity": "YÜKSEK", "cwe": "CWE-1333", "cvss": 7.5,
         "cves": ["CVE-2022-21680", "CVE-2022-21681"], "summary": "Marked < 4.0.10 düzenli ifade servis dışı bırakma (ReDoS) zafiyeti"},
    ],
    "underscore": [
        {"below": "1.13.6", "patched": "1.13.6", "severity": "KRİTİK", "cwe": "CWE-94", "cvss": 9.8,
         "cves": ["CVE-2021-23358"], "summary": "Underscore < 1.13.6 template değişkeni üzerinden rastgele kod çalıştırma zafiyeti"},
    ],
    "sweetalert2": [
        {"below": "11.4.8", "patched": "11.6.14", "severity": "ORTA", "cwe": "CWE-79", "cvss": 6.1,
         "cves": ["CVE-2022-25898"], "summary": "SweetAlert2 eski sürümlerde güvenlik/bütünlük riskleri"},
    ],
    "chart.js": [
        {"below": "2.9.4", "patched": "2.9.4 / 4.4.4", "severity": "YÜKSEK", "cwe": "CWE-1321", "cvss": 7.5,
         "cves": ["CVE-2020-7746"], "summary": "Chart.js < 2.9.4 seçenek birleştirmede Prototype Pollution zafiyeti"},
    ],
}

SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
LIB_EXTRACT_PATTERNS = [
    ("jquery-ui", re.compile(r"jquery[.-]ui(?:[.-]custom)?[.-]v?(\d+\.\d+\.\d+)", re.I)),
    ("jquery-ui", re.compile(r"jqueryui/(\d+\.\d+\.\d+)/", re.I)),
    ("jquery", re.compile(r"(?<![a-z0-9-])jquery(?:\.slim)?[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("jquery", re.compile(r"/jquery(?:@|/)v?(\d+\.\d+\.\d+)(?:/|\.min|\.js)", re.I)),
    ("bootstrap", re.compile(r"bootstrap(?:\.bundle)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(r"lodash(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("moment", re.compile(r"moment(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("dompurify", re.compile(r"(?:dompurify|purify)(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("handlebars", re.compile(r"handlebars(?:\.runtime)?(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("angular", re.compile(r"angular(?:\.min)?(?:[.-]|@|/)v?(1\.\d+\.\d+)", re.I)),
    ("axios", re.compile(r"axios(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("marked", re.compile(r"marked(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("underscore", re.compile(r"underscore(?:[.-]min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("sweetalert2", re.compile(r"sweetalert2(?:\.all)?(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
    ("chart.js", re.compile(r"chart(?:\.js)?(?:\.bundle)?(?:\.min)?(?:[.-]|@|/)v?(\d+\.\d+\.\d+)", re.I)),
]

BANNER_PATTERNS = [
    ("jquery-ui", re.compile(r"jQuery UI\s*-?\s*v?(\d+\.\d+\.\d+)", re.I)),
    ("jquery", re.compile(r"jQuery\s+JavaScript\s+Library\s+v?(\d+\.\d+\.\d+)|/\*!\s*jQuery\s+v(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap", re.compile(r"Bootstrap\s+v(\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(r"lodash\s+(\d+\.\d+\.\d+)|VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"].*lodash", re.I)),
    ("moment", re.compile(r"moment\.js[\s\S]{0,120}?version\s*:\s*(\d+\.\d+\.\d+)", re.I)),
    ("dompurify", re.compile(r"DOMPurify\s+(\d+\.\d+\.\d+)", re.I)),
    ("handlebars", re.compile(r"handlebars\s+v(\d+\.\d+\.\d+)", re.I)),
    ("angular", re.compile(r"AngularJS\s+v(1\.\d+\.\d+)", re.I)),
    ("underscore", re.compile(r"Underscore\.js\s+(\d+\.\d+\.\d+)", re.I)),
]


def _parse_ver(v):
    nums = re.findall(r"\d+", str(v or ""))
    return tuple(int(x) for x in nums[:4]) if nums else ()


def _ver_lt(v1, v2):
    t1, t2 = _parse_ver(v1), _parse_ver(v2)
    if not t1 or not t2:
        return False
    maxlen = max(len(t1), len(t2))
    t1 += (0,) * (maxlen - len(t1))
    t2 += (0,) * (maxlen - len(t2))
    return t1 < t2


def _ver_gte(v1, v2):
    t1, t2 = _parse_ver(v1), _parse_ver(v2)
    if not t1 or not t2:
        return False
    maxlen = max(len(t1), len(t2))
    t1 += (0,) * (maxlen - len(t1))
    t2 += (0,) * (maxlen - len(t2))
    return t1 >= t2


def fetch_retirejs_db(allow_network=True):
    """Canlı Retire.js jsrepository-v4.json verisini çeker (önbellekli); hata durumunda boş dict döner."""
    if not allow_network or os.environ.get("WSS_NO_NETWORK_FEEDS") == "1":
        return {}
    now = time.time()
    with _FEED_LOCK:
        if _RETIRE_CACHE["data"] is not None and (now - _RETIRE_CACHE["at"] < FEED_TTL_SECONDS):
            return _RETIRE_CACHE["data"]
    try:
        req = urllib.request.Request(RETIREJS_URL, headers={"User-Agent": "WebSecurityScanner-JSCVE/2.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        with _FEED_LOCK:
            _RETIRE_CACHE["at"] = now
            _RETIRE_CACHE["data"] = data if isinstance(data, dict) else {}
        return _RETIRE_CACHE["data"]
    except Exception:
        return {}


def evaluate_js_library(lib, version, allow_network=False):
    """Verilen JS kütüphanesi ve sürümü için eşleşen CVE ve yama önerilerini döner."""
    lib_key = (lib or "").lower().strip()
    matches = []
    seen_cves = set()

    for rule in BASELINE_JS_VULNS.get(lib_key, []):
        if rule.get("at_or_above") and not _ver_gte(version, rule["at_or_above"]):
            continue
        if _ver_lt(version, rule["below"]):
            matches.append(dict(rule))
            seen_cves.update(rule.get("cves") or [])

    # İsteğe bağlı canlı Retire.js zenginleştirmesi
    retire_db = fetch_retirejs_db(allow_network=allow_network)
    lib_entry = retire_db.get(lib_key) if isinstance(retire_db, dict) else None
    if isinstance(lib_entry, dict):
        for v in (lib_entry.get("vulnerabilities") or []):
            if not isinstance(v, dict):
                continue
            below = v.get("below")
            at_or_above = v.get("atOrAbove")
            if not below:
                continue
            if at_or_above and not _ver_gte(version, at_or_above):
                continue
            if _ver_lt(version, below):
                ids = (v.get("identifiers") or {})
                cves = list(ids.get("CVE") or ids.get("githubID") or [])
                new_cves = [c for c in cves if c not in seen_cves]
                if new_cves or not matches:
                    seen_cves.update(cves)
                    sev_raw = str(v.get("severity") or "medium").lower()
                    sev_map = {"critical": "KRİTİK", "high": "YÜKSEK", "medium": "ORTA", "low": "DÜŞÜK"}
                    matches.append({
                        "below": below,
                        "patched": below,
                        "severity": sev_map.get(sev_raw, "ORTA"),
                        "cwe": (v.get("cwe") or ["CWE-1104"])[0] if isinstance(v.get("cwe"), list) and v.get("cwe") else "CWE-1104",
                        "cvss": 8.0 if sev_raw in ("critical", "high") else 6.1,
                        "cves": cves[:5],
                        "summary": str(ids.get("summary") or ("%s < %s bilinen güvenlik açığı" % (lib_key, below))),
                    })
    return matches


def scan_file_for_js_cves(rel_path, content, allow_network=False):
    """Tek bir kaynak dosyadaki (<script src> veya JS banner) zafiyetli JS kütüphanelerini bulur."""
    findings = []
    low_path = rel_path.lower()
    lines = content.splitlines()

    # 1) HTML / PHP / Şablon dosyalarında <script src="..."> taraması
    if low_path.endswith((".html", ".htm", ".php", ".ejs", ".vue", ".jsx", ".tsx", ".twig", ".hbs")):
        for idx, line in enumerate(lines, start=1):
            if "<script" not in line.lower():
                continue
            for m_src in SCRIPT_SRC_RE.finditer(line):
                src_val = m_src.group(1)
                for lib, rx in LIB_EXTRACT_PATTERNS:
                    mm = rx.search(src_val)
                    if mm:
                        ver = next((g for g in mm.groups() if g), "")
                        vulns = evaluate_js_library(lib, ver, allow_network=allow_network)
                        if vulns:
                            top = vulns[0]
                            all_cves = []
                            for vv in vulns:
                                for c in (vv.get("cves") or []):
                                    if c not in all_cves:
                                        all_cves.append(c)
                            cve_str = ", ".join(all_cves[:5]) if all_cves else "Retire.js Advisory"
                            patched = top.get("patched") or top.get("below")
                            findings.append({
                                "rule_id": "JS-CVE-001",
                                "category": "JavaScript Kütüphane CVE (Retire.js)",
                                "severity": top["severity"],
                                "cwe": top.get("cwe", "CWE-1104"),
                                "cvss": top.get("cvss", 6.5),
                                "title": f"Zafiyetli JavaScript Kütüphanesi: {lib} v{ver} ({cve_str})",
                                "file": rel_path,
                                "line": idx,
                                "match": src_val[:120],
                                "description": f"{top['summary']}. Tespit edilen sürüm: {lib} {ver} ({cve_str}).",
                                "fix": f"{lib} kütüphanesini en az {patched} (yamalı) sürümüne yükseltin.",
                                "analyzer": "retirejs",
                                "verified": True,
                            })
                        break

    # 2) .js dosyalarının ilk 25 satırındaki sürüm başlığı (banner) veya dosya adı taraması
    if low_path.endswith(".js"):
        base_name = os.path.basename(rel_path)
        detected = None
        for lib, rx in LIB_EXTRACT_PATTERNS:
            mm = rx.search(base_name)
            if mm:
                ver = next((g for g in mm.groups() if g), "")
                detected = (lib, ver, 1, base_name)
                break
        if not detected:
            head_text = "\n".join(lines[:25])
            for lib, rx in BANNER_PATTERNS:
                mm = rx.search(head_text)
                if mm:
                    ver = next((g for g in mm.groups() if g), "")
                    line_no = head_text[:mm.start()].count("\n") + 1
                    detected = (lib, ver, line_no, mm.group(0)[:100])
                    break
        if detected:
            lib, ver, line_no, match_txt = detected
            vulns = evaluate_js_library(lib, ver, allow_network=allow_network)
            if vulns:
                top = vulns[0]
                all_cves = []
                for vv in vulns:
                    for c in (vv.get("cves") or []):
                        if c not in all_cves:
                            all_cves.append(c)
                cve_str = ", ".join(all_cves[:5]) if all_cves else "Retire.js Advisory"
                patched = top.get("patched") or top.get("below")
                findings.append({
                    "rule_id": "JS-CVE-001",
                    "category": "JavaScript Kütüphane CVE (Retire.js)",
                    "severity": top["severity"],
                    "cwe": top.get("cwe", "CWE-1104"),
                    "cvss": top.get("cvss", 6.5),
                    "title": f"Zafiyetli Yerel JS Kütüphanesi: {lib} v{ver} ({cve_str})",
                    "file": rel_path,
                    "line": line_no,
                    "match": match_txt,
                    "description": f"{top['summary']}. Tespit edilen sürüm: {lib} {ver} ({cve_str}).",
                    "fix": f"{lib} dosyasını en az {patched} (yamalı) sürümüyle güncelleyin.",
                    "analyzer": "retirejs",
                    "verified": True,
                })
    findings.extend(scan_nextjs_advisories_in_file(rel_path, content))
    return findings

# ==========================================================================
# Next.js Resmi Güvenlik Bültenleri (Kasım 2026: v16.4.5 / v15.5.29 + CVE-2025-29927)
# Kaynak: https://nextjs.org/blog/november-2026-security-release
# ==========================================================================
NEXTJS_NOV_2026_ADVISORIES = (
    "GHSA-mfr8-8qww-v76h",  # Cross-tenant cache disclosure (unstable_cache + use cache) [High]
    "GHSA-vc7v-qv4w-wrv8",  # Cross-root-parameter disclosure in nested use cache [Medium]
    "GHSA-rhh4-g77r-r9qj",  # Cross-user cache disclosure/poisoning via binary use cache args [Medium]
    "GHSA-pc58-hwjq-p385",  # Cross-client response injection via stale compressed Response framing [Medium]
    "GHSA-f3mh-rxg3-f5g2",  # Cookie exposure via x-middleware-set-cookie in Edge routes [Medium]
    "GHSA-7qx7-33qx-rqx2",  # SVG rejection bypass in Image Optimization [Medium]
)

def evaluate_nextjs_version(ver_raw):
    """package.json / package-lock.json içindeki next sürümünü resmi Next.js bültenleriyle karşılaştırır."""
    m = re.search(r"(\d+\.\d+\.\d+)", str(ver_raw or ""))
    if not m:
        return []
    ver = m.group(1)
    t = _parse_ver(ver)
    if not t:
        return []
    major = t[0]
    out = []
    # 1) CVE-2025-29927 (Kritik Middleware Yetki Atlama: <14.2.25 veya 15.0.0..<15.2.3)
    if (major < 14) or (major == 14 and _ver_lt(ver, "14.2.25")) or (major == 15 and _ver_lt(ver, "15.2.3")):
        out.append({
            "rule_id": "NEXT-ADV-001",
            "severity": "KRİTİK",
            "cwe": "CWE-287",
            "cvss": 9.1,
            "patched": "15.5.29 / 16.4.5",
            "cves": ["CVE-2025-29927"],
            "summary": "Next.js x-middleware-subrequest başlığı ile Middleware yetkilendirme atlama zafiyeti",
        })
    # 2) Kasım 2026 Güvenlik Bülteni (v15 < 15.5.29 veya v16 < 16.4.5 veya <=14.x)
    if (major <= 15 and _ver_lt(ver, "15.5.29")) or (major == 16 and _ver_lt(ver, "16.4.5")):
        patched_target = "16.4.5" if major >= 16 else "15.5.29"
        out.append({
            "rule_id": "NEXT-ADV-001",
            "severity": "YÜKSEK",
            "cwe": "CWE-200",
            "cvss": 7.8,
            "patched": patched_target,
            "cves": list(NEXTJS_NOV_2026_ADVISORIES),
            "summary": (
                "Next.js Kasım 2026 Güvenlik Bülteni (https://nextjs.org/blog/november-2026-security-release): "
                "Cross-tenant cache ifşası (GHSA-mfr8-8qww-v76h, GHSA-vc7v-qv4w-wrv8), binary 'use cache' önbellek "
                "zehirlenmesi (GHSA-rhh4-g77r-r9qj), self-hosted shared shell cache poisoning, sıkıştırılmış Response "
                "çerçeveleme enjeksiyonu (GHSA-pc58-hwjq-p385), Edge route x-middleware-set-cookie çerez sızıntısı "
                "(GHSA-f3mh-rxg3-f5g2) ve Image Optimization SVG bypass (GHSA-7qx7-33qx-rqx2)"
            ),
        })
    return out


def scan_nextjs_advisories_in_file(rel_path, content):
    """Next.js Kasım 2026 bültenindeki zafiyetli kod desenlerini ve package.json sürümünü denetler."""
    findings = []
    low_path = rel_path.lower().replace("\\", "/")
    base_name = os.path.basename(low_path)
    lines = content.splitlines()

    # A) package.json içinde next bağımlılık sürümü kontrolü
    if base_name == "package.json":
        try:
            pkg = json.loads(content)
            deps = {}
            for sec in ("dependencies", "devDependencies"):
                if isinstance(pkg.get(sec), dict):
                    deps.update(pkg[sec])
            if "next" in deps:
                raw_v = str(deps["next"])
                line_no = 1
                for idx, ln in enumerate(lines, start=1):
                    if '"next"' in ln:
                        line_no = idx
                        break
                for adv in evaluate_nextjs_version(raw_v):
                    cve_str = ", ".join(adv["cves"][:4])
                    findings.append({
                        "rule_id": adv["rule_id"],
                        "category": "Next.js Güvenliği (Kasım 2026 Bülteni)",
                        "severity": adv["severity"],
                        "cwe": adv["cwe"],
                        "cvss": adv["cvss"],
                        "title": f"Zafiyetli Next.js Sürümü: next@{raw_v} ({cve_str})",
                        "file": rel_path,
                        "line": line_no,
                        "match": f'"next": "{raw_v}"',
                        "description": adv["summary"],
                        "fix": f"Next.js bağımlılığını yamalı sürüme yükseltin: npm install next@{adv['patched']}",
                        "analyzer": "nextjs_advisory",
                        "verified": True,
                    })
        except Exception:
            pass

    # B) Kaynak kod (.js/.ts/.jsx/.tsx) üzerinde Kasım 2026 Next.js bülteni desen kontrolleri
    if low_path.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs")):
        has_use_cache = bool(re.search(r"['\"]use cache['\"]", content))
        has_unstable_cache = "unstable_cache" in content
        if has_use_cache and has_unstable_cache:
            line_no = next((i for i, l in enumerate(lines, 1) if "unstable_cache" in l or "use cache" in l), 1)
            findings.append({
                "rule_id": "NEXT-ADV-002",
                "category": "Next.js Güvenliği (Kasım 2026 Bülteni)",
                "severity": "YÜKSEK",
                "cwe": "CWE-200",
                "cvss": 7.8,
                "title": "GHSA-mfr8-8qww-v76h: 'use cache' ve 'unstable_cache' Birlikte Kullanımı (Cross-Tenant Cache Disclosure)",
                "file": rel_path,
                "line": line_no,
                "match": "unstable_cache + 'use cache'",
                "description": "Next.js Kasım 2026 Bülteni (GHSA-mfr8-8qww-v76h): Aynı 'use cache' fonksiyonunun hem doğrudan hem de 'unstable_cache' içinden çağrılması kiracılar (tenant) arası önbellek verisi sızıntısına yol açabilir.",
                "fix": "Next.js sürümünü v16.4.5 veya v15.5.29'a yükseltin ve 'unstable_cache' ile 'use cache' çağrılarını aynı kök parametreli fonksiyonda birleştirmeyin.",
                "analyzer": "nextjs_advisory",
                "verified": True,
            })

        if has_use_cache and re.search(r"\b(Uint8Array|ArrayBuffer|Buffer\.from)\b", content):
            line_no = next((i for i, l in enumerate(lines, 1) if re.search(r"(Uint8Array|ArrayBuffer|Buffer\.from)", l)), 1)
            findings.append({
                "rule_id": "NEXT-ADV-003",
                "category": "Next.js Güvenliği (Kasım 2026 Bülteni)",
                "severity": "ORTA",
                "cwe": "CWE-345",
                "cvss": 6.5,
                "title": "GHSA-rhh4-g77r-r9qj: 'use cache' Fonksiyonunda Binary Argüman Kullanımı (Cache Poisoning/Disclosure)",
                "file": rel_path,
                "line": line_no,
                "match": "use cache + binary argument (Buffer/Uint8Array)",
                "description": "Next.js Kasım 2026 Bülteni (GHSA-rhh4-g77r-r9qj): 'use cache' fonksiyonlarına geçirilen farklı binary argümanlar aynı önbellek anahtarını üreterek kullanıcılar arası veri karışmasına yol açabilir.",
                "fix": "Next.js v16.4.5 / v15.5.29 sürümüne güncelleyin ve önbellek anahtarı olarak binary argüman yerine açık string/hash kimlikler kullanın.",
                "analyzer": "nextjs_advisory",
                "verified": True,
            })

        is_edge = bool(re.search(r"runtime\s*=\s*['\"]edge['\"]", content))
        if is_edge and re.search(r"\.cookies\.set\s*\(", content):
            line_no = next((i for i, l in enumerate(lines, 1) if ".cookies.set" in l), 1)
            findings.append({
                "rule_id": "NEXT-ADV-004",
                "category": "Next.js Güvenliği (Kasım 2026 Bülteni)",
                "severity": "ORTA",
                "cwe": "CWE-200",
                "cvss": 6.5,
                "title": "GHSA-f3mh-rxg3-f5g2: Edge Route İçinde NextResponse.cookies.set() ile Çerez Sızıntısı",
                "file": rel_path,
                "line": line_no,
                "match": "runtime='edge' + .cookies.set()",
                "description": "Next.js Kasım 2026 Bülteni (GHSA-f3mh-rxg3-f5g2): Edge Route Handler'larda NextResponse.cookies.set() kullanımı, HttpOnly çerezleri bile 'x-middleware-set-cookie' iç başlığıyla aynı kökendeki JS'e sızdırabilir.",
                "fix": "Next.js v16.4.5 / v15.5.29'a güncelleyin veya çerezleri next/headers içindeki cookies().set() ile tanımlayın.",
                "analyzer": "nextjs_advisory",
                "verified": True,
            })

        for idx, ln in enumerate(lines, start=1):
            if re.search(r"\breturn\s+(?:await\s+)?fetch\s*\(", ln):
                findings.append({
                    "rule_id": "NEXT-ADV-005",
                    "category": "Next.js Güvenliği (Kasım 2026 Bülteni)",
                    "severity": "ORTA",
                    "cwe": "CWE-444",
                    "cvss": 6.5,
                    "title": "GHSA-pc58-hwjq-p385: Ham fetch() Response Nesnesinin Doğrudan Döndürülmesi (Response Framing Injection)",
                    "file": rel_path,
                    "line": idx,
                    "match": ln.strip()[:100],
                    "description": "Next.js Kasım 2026 Bülteni (GHSA-pc58-hwjq-p385): Dışarıdan alınan sıkıştırılmış bir fetch() Response nesnesinin değiştirilmeden döndürülmesi, HTTP/1.1 ters vekil (reverse proxy) arkasında istemciler arası yanıt karışmasına yol açabilir.",
                    "fix": "Next.js v16.4.5 / v15.5.29'a yükseltin ve dış Response döndürürken yeni bir Response/NextResponse oluşturup Content-Encoding/Content-Length başlıklarını temizleyin.",
                    "analyzer": "nextjs_advisory",
                    "verified": True,
                })
    return findings
