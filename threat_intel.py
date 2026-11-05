#!/usr/bin/env python3
"""
threat_intel.py — Bileşen sürümü → bilinen zafiyet eşleştirmesi (Faz 3, isteğe bağlı).

PentAGI'nin Searcher ajanının (NVD, Sploitus vb.) bu araca uyarlanmış, deterministik ve
yalnızca Python standart kütüphanesi kullanan hâli:
  - Sunucu başlıkları (Server, X-Powered-By, X-Generator), <meta name="generator"> ve
    <script src> yollarından ürün + sürüm çıkarılır.
  - Sunucu yazılımları için NVD CVE API 2.0 (cpeName + isVulnerable), JS kütüphaneleri için
    OSV (npm) sorgulanır; CVE'ler CISA KEV (istismar edildiği bilinen açıklar) ile işaretlenir.
  - Dışarıya YALNIZCA ürün adı + sürüm gönderilir; hedefin adresi / alan adı asla gönderilmez.
  - Sonuçlar her zaman "doğrulanmalı" (needs_validation) işaretlenir: Linux dağıtımları güvenlik
    yamalarını sürüm numarasını değiştirmeden geri taşıyabildiği için (backport) banner sürümüne
    dayalı eşleşmeler yanlış pozitif olabilir.
  - Yanıtlar 24 saat yerel önbellekte tutulur; NVD anahtarsız kullanımda istekler arası 6,5 sn
    beklenir (NVD_API_KEY ortam değişkeni ile hızlanır). Tarama başına en fazla 6 NVD isteği.
Varsayılan olarak KAPALIDIR; tarama isteğinde threat_intel bayrağıyla açılır.
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import scan_history
import js_cve_scanner

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "WebSecurityScanner-ThreatIntel/1.0"
CACHE_TTL_SECONDS = 24 * 3600
MAX_COMPONENTS = 6
MAX_NVD_CALLS = 6
MAX_VULNS_IN_FINDING = 8
NVD_SPACING_NO_KEY = 6.5
NVD_SPACING_WITH_KEY = 0.7
TEST_NAME = "Tehdit İstihbaratı (OSV / NVD / CISA KEV)"
NOTE = ("Sürüm eşleşmeleri doğrulanmalıdır: dağıtımlar güvenlik yamalarını sürüm numarasını "
        "değiştirmeden geri taşıyabilir (backport).")

SERVER_PRODUCTS = {
    "nginx": ("nginx", (("f5", "nginx"), ("nginx", "nginx"))),
    "apache": ("Apache HTTP Server", (("apache", "http_server"),)),
    "php": ("PHP", (("php", "php"),)),
    "openssl": ("OpenSSL", (("openssl", "openssl"),)),
    "microsoft-iis": ("Microsoft IIS", (("microsoft", "internet_information_services"),)),
    "lighttpd": ("lighttpd", (("lighttpd", "lighttpd"),)),
    "openresty": ("OpenResty", (("openresty", "openresty"),)),
    "caddy": ("Caddy", (("caddyserver", "caddy"),)),
    "tomcat": ("Apache Tomcat", (("apache", "tomcat"),)),
    "wordpress": ("WordPress", (("wordpress", "wordpress"),)),
    "drupal": ("Drupal", (("drupal", "drupal"),)),
}
JS_LIBS = ("jquery-ui", "jquery", "bootstrap", "angularjs", "angular", "vue", "react-dom", "react",
           "lodash", "moment", "handlebars", "underscore", "dompurify", "axios")
JS_NPM_NAME = {"angularjs": "angular"}

_BANNER = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]{1,40})/v?(\d+(?:\.\d+){1,3}[a-z]?)")
_META_GEN = re.compile(r"<meta\b[^>]{0,300}?\bname=[\"']generator[\"'][^>]{0,300}?\bcontent=[\"']([^\"']{1,120})[\"']", re.I)
_META_GEN2 = re.compile(r"<meta\b[^>]{0,300}?\bcontent=[\"']([^\"']{1,120})[\"'][^>]{0,300}?\bname=[\"']generator[\"']", re.I)
_SCRIPT_SRC = re.compile(r"<script\b[^>]{0,400}?\bsrc=[\"']([^\"']{1,500})[\"']", re.I)
_GEN_VER = re.compile(r"^\s*([A-Za-z][A-Za-z ]{1,30}?)\s+v?(\d+(?:\.\d+){1,3})")
_JS_PATTERNS = {
    lib: (re.compile(r"(?:^|[/@._=-])" + re.escape(lib) + r"(?:\.js)?(?:\.min)?[-@/]v?(\d+\.\d+(?:\.\d+)?)"),
          re.compile(r"(?:^|[/@._=-])" + re.escape(lib) + r"(?:\.min)?\.js\?(?:ver|v|version)=v?(\d+\.\d+(?:\.\d+)?)"))
    for lib in JS_LIBS
}
_SEV_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "MODERATE": 5.5, "LOW": 2.0}

_NVD_LOCK = threading.Lock()
_LAST_NVD_CALL = [0.0]


# ---------------------------------------------------------------- bileşen çıkarımı
def extract_components(headers=None, html="", fingerprints=None):
    comps, seen = [], set()

    def add(kind, key, version, source, evidence):
        if (kind, key, version) in seen or len(comps) >= MAX_COMPONENTS:
            return
        seen.add((kind, key, version))
        if kind == "server":
            name, cpes = SERVER_PRODUCTS[key]
            comps.append({"kind": "server", "key": key, "name": name, "version": version, "cpes": list(cpes),
                          "source": source, "evidence": evidence[:200]})
        else:
            comps.append({"kind": "js", "key": key, "name": key, "npm": JS_NPM_NAME.get(key, key),
                          "version": version, "source": source, "evidence": evidence[:200]})

    hdrs = {str(k).lower(): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {}
    for hname, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"), ("x-generator", "X-Generator")):
        value = hdrs.get(hname, "")
        for m in _BANNER.finditer(value):
            key = m.group(1).lower()
            if key in SERVER_PRODUCTS:
                add("server", key, m.group(2), label + " başlığı", "%s: %s" % (label, value[:150]))
    for fp in (fingerprints or []):
        text = str(fp)
        for m in _BANNER.finditer(text):
            key = m.group(1).lower()
            if key in SERVER_PRODUCTS:
                add("server", key, m.group(2), "teknoloji parmak izi", text[:150])
    page = (html or "")[:400000]
    for rx in (_META_GEN, _META_GEN2):
        for m in rx.finditer(page):
            g = _GEN_VER.match(m.group(1))
            if g:
                key = g.group(1).strip().lower().replace(" ", "-")
                if key in SERVER_PRODUCTS:
                    add("server", key, g.group(2), "generator meta etiketi", "generator: " + m.group(1)[:120])
    for m in _SCRIPT_SRC.finditer(page):
        src = m.group(1)
        low = src.lower()
        for lib in JS_LIBS:
            if lib not in low:
                continue
            hit = None
            for rx in _JS_PATTERNS[lib]:
                mm = rx.search(low)
                if mm:
                    hit = mm.group(1)
                    break
            if hit:
                add("js", lib, hit, "<script src>", "script: " + src[:150])
                break
    return comps


# ---------------------------------------------------------------- dış kaynaklar
def _http_json(url, data=None, headers=None, timeout=20):
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        hdrs["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _nvd_spacing():
    return NVD_SPACING_WITH_KEY if os.environ.get("NVD_API_KEY", "").strip() else NVD_SPACING_NO_KEY


def _cvss(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            return data.get("baseScore"), (data.get("baseSeverity") or entries[0].get("baseSeverity") or "")
    return None, ""


def _parse_nvd(data):
    out = []
    for item in (data.get("vulnerabilities") or []):
        cve = (item or {}).get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        score, sev = _cvss(cve.get("metrics") or {})
        desc = next((d.get("value", "") for d in (cve.get("descriptions") or []) if d.get("lang") == "en"), "")
        out.append({"id": cid, "aliases": [], "score": score, "severity": str(sev or "").upper(),
                    "summary": desc[:220], "source": "NVD"})
    return out


def _nvd_query(vendor, product, version):
    cpe = "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*" % (vendor, product, version)
    url = NVD_URL + "?" + urllib.parse.urlencode({"cpeName": cpe}) + "&isVulnerable"
    headers = {}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    for attempt in range(2):
        with _NVD_LOCK:
            wait = _LAST_NVD_CALL[0] + _nvd_spacing() - time.time()
            if wait > 0:
                time.sleep(wait)
            try:
                return _parse_nvd(_http_json(url, headers=headers, timeout=25))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return []  # CPE sözlükte yok → bilinen kayıt yok
                if e.code in (403, 429, 503) and attempt == 0:
                    continue  # hız sınırı: bir aralık bekleyip bir kez daha dene
                raise
            finally:
                _LAST_NVD_CALL[0] = time.time()
    return []


def _osv_npm(name, version):
    try:
        from sast_engine import _osv_query  # mevcut OSV istemcisi (SAST bağımlılık denetimi)
        data = _osv_query(name, "npm", version)
    except ImportError:
        data = _http_json(OSV_URL, data={"package": {"name": name, "ecosystem": "npm"}, "version": version})
    out = []
    for rj in js_cve_scanner.evaluate_js_library(name, version, allow_network=True):
        for rcve in (rj.get("cves") or ["Retire.js"]):
            out.append({"id": rcve, "cves": [rcve] if rcve.startswith("CVE-") else [],
                        "cvss": rj.get("cvss", 6.5),
                        "summary": "%s (Yamalı sürüm: >= %s)" % (rj.get("summary", ""), rj.get("patched", rj.get("below", ""))),
                        "url": "https://github.com/RetireJS/retire.js"})
    for v in (data.get("vulns") or []):
        aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str)]
        sev = str((v.get("database_specific") or {}).get("severity") or "").upper()
        out.append({"id": v.get("id") or "?", "aliases": aliases, "score": None,
                    "severity": "MEDIUM" if sev == "MODERATE" else sev,
                    "summary": str(v.get("summary") or v.get("details") or "")[:220], "source": "OSV"})
    return out


def _kev_fetch():
    data = _http_json(KEV_URL, timeout=30)
    return {v["cveID"]: {"ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                         "added": v.get("dateAdded", "")}
            for v in (data.get("vulnerabilities") or []) if isinstance(v, dict) and v.get("cveID")}


# ---------------------------------------------------------------- bulgu üretimi
def _severity_label(vulns, kev_count):
    best = 0.0
    for v in vulns:
        best = max(best, float(v.get("score") or _SEV_SCORE.get(v.get("severity"), 0.0)))
    if kev_count:
        best = max(best, 7.0)
    if best >= 9.0:
        return "KRİTİK"
    if best >= 7.0:
        return "YÜKSEK"
    if best >= 4.0:
        return "ORTA"
    return "DÜŞÜK"


def _build_finding(comp, vulns, kev):
    enriched = []
    for v in vulns:
        cves = ([v["id"]] if str(v.get("id", "")).startswith("CVE-") else []) + \
               [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        kev_hit = next((c for c in cves if c in kev), None)
        enriched.append(dict(v, cves=cves[:3], kev=bool(kev_hit),
                             ransomware=bool(kev_hit and kev[kev_hit].get("ransomware"))))
    enriched.sort(key=lambda v: (not v["kev"], -float(v.get("score") or _SEV_SCORE.get(v.get("severity"), 0.0))))
    kev_count = sum(1 for v in enriched if v["kev"])
    labels = []
    for v in enriched[:5]:
        label = v["id"]
        if v.get("cves") and not label.startswith("CVE-"):
            label += " (" + v["cves"][0] + ")"
        if v.get("score") is not None:
            label += " CVSS %.1f" % float(v["score"])
        elif v.get("severity"):
            label += " " + v["severity"]
        if v["kev"]:
            label += " · CISA KEV" + (" · fidye yazılımı" if v["ransomware"] else "")
        labels.append(label)
    source = "OSV (npm)" if comp["kind"] == "js" else "NVD (CPE " + ", ".join("%s:%s" % c for c in comp["cpes"]) + ")"
    title = "Bilinen zafiyetli bileşen (doğrulanmalı): %s %s — %d kayıt%s" % (
        comp["name"], comp["version"], len(enriched), (", %d tanesi CISA KEV'de" % kev_count) if kev_count else "")
    return {
        "test": TEST_NAME,
        "severity": _severity_label(enriched, kev_count),
        "title": title,
        "evidence": ("%s | Öne çıkanlar: %s | Kaynak: %s" % (comp["evidence"], "; ".join(labels), source))[:900],
        "cwe": "CWE-1395",
        "fix": ("Sunucudaki gerçek paket sürümünü doğrulayın (dağıtımlar yamaları sürüm numarasını değiştirmeden "
                "geri taşıyabilir); gerekiyorsa güncelleyin ve sürüm bilgisini yanıt başlıklarından gizleyin."),
        "verdict": "needs_validation",
        "component": {"name": comp["name"], "version": comp["version"], "source": comp["source"], "kind": comp["kind"]},
        "intel": {"total": len(enriched), "kev_count": kev_count,
                  "top": [{"id": v["id"], "cves": v["cves"], "score": v.get("score"), "severity": v.get("severity"),
                           "kev": v["kev"], "summary": v.get("summary", "")[:160]}
                          for v in enriched[:MAX_VULNS_IN_FINDING]]},
    }


def run_threat_intel(headers=None, html="", fingerprints=None, emit=None):
    """(bulgular, özet) döndürür. Hiçbir koşulda istisna fırlatmaz (hata özetteki errors listesine yazılır)."""
    started = time.time()
    summary = {"enabled": True, "components": [], "lookups": 0, "cache_hits": 0, "errors": [],
               "sources": [], "finding_count": 0, "kev_matches": 0, "duration_ms": 0, "note": NOTE}

    def say(message):
        if emit:
            try:
                emit("system", message)
            except Exception:
                pass

    try:
        comps = extract_components(headers, html, fingerprints)
    except Exception as e:
        summary["errors"].append("Bileşen çıkarımı başarısız: %s" % str(e)[:120])
        comps = []
    summary["components"] = [{"name": c["name"], "version": c["version"], "source": c["source"]} for c in comps]
    if not comps:
        say("🌐 Tehdit istihbaratı: sürümü okunabilen bileşen bulunamadı.")
        summary["duration_ms"] = int((time.time() - started) * 1000)
        return [], summary
    say("🌐 Tehdit istihbaratı: %d bileşen sorgulanıyor (dışarıya yalnızca ürün + sürüm gider)…" % len(comps))

    kev = scan_history.cache_get("cisa_kev", CACHE_TTL_SECONDS)
    if kev is None:
        try:
            kev = _kev_fetch()
            scan_history.cache_set("cisa_kev", kev)
        except Exception as e:
            kev = {}
            summary["errors"].append("CISA KEV kataloğu alınamadı: %s" % str(e)[:120])
    else:
        summary["cache_hits"] += 1
    if kev:
        summary["sources"].append("CISA KEV")

    findings, nvd_calls = [], 0
    for comp in comps:
        vulns, seen_ids = [], set()
        try:
            if comp["kind"] == "js":
                plan = [("osv:npm:%s:%s" % (comp["npm"], comp["version"]),
                         lambda c=comp: _osv_npm(c["npm"], c["version"]), "OSV")]
            else:
                plan = [("nvd:%s:%s:%s" % (vendor, product, comp["version"]),
                         lambda v=vendor, p=product, ver=comp["version"]: _nvd_query(v, p, ver), "NVD")
                        for vendor, product in comp["cpes"]]
            for key, fetch, src in plan:
                cached = scan_history.cache_get(key, CACHE_TTL_SECONDS)
                if cached is not None:
                    result = cached
                    summary["cache_hits"] += 1
                else:
                    if src == "NVD":
                        if nvd_calls >= MAX_NVD_CALLS:
                            summary["errors"].append("NVD sorgu sınırı (%d) doldu; %s %s atlandı."
                                                     % (MAX_NVD_CALLS, comp["name"], comp["version"]))
                            continue
                        nvd_calls += 1
                    result = fetch()
                    scan_history.cache_set(key, result)
                summary["lookups"] += 1
                if src not in summary["sources"]:
                    summary["sources"].append(src)
                for v in result or []:
                    if v.get("id") not in seen_ids:
                        seen_ids.add(v.get("id"))
                        vulns.append(v)
        except Exception as e:
            summary["errors"].append("%s %s sorgulanamadı: %s" % (comp["name"], comp["version"], str(e)[:120]))
            continue
        if vulns:
            findings.append(_build_finding(comp, vulns, kev or {}))
    summary["finding_count"] = len(findings)
    summary["kev_matches"] = sum(f["intel"]["kev_count"] for f in findings)
    summary["duration_ms"] = int((time.time() - started) * 1000)
    say("🌐 Tehdit istihbaratı tamam: %d bileşen, %d eşleşme (%d CISA KEV) — sonuçlar doğrulanmalı."
        % (len(comps), len(findings), summary["kev_matches"]))
    return findings, summary
