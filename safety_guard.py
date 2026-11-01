#!/usr/bin/env python3
"""
safety_guard.py — LLM / AI tarafından önerilen problar için kod düzeyinde güvenlik korumaları.

PentAGI'deki "araç çağrısı sınırları + izolasyon" yaklaşımının bu araca uyarlanmış hâli.
Prompt kuralları tek başına yeterli değildir: hedef sayfadaki bir metin prompt injection ile
ajanı başka bir adrese ya da yıkıcı bir payload'a yönlendirebilir. Bu modül, LLM ne önerirse
önersin uygulanan deterministik kontroller sağlar:

  1) Kapsam: prob URL'si, etik onayı verilmiş hedefle AYNI scheme + host + port olmalıdır.
  2) Payload: yıkıcı (veri silen/değiştiren), hizmeti aksatan veya kimlik bilgisi sızdırmaya
     yönelik payload'lar gönderilmeden reddedilir (salt-okunur prob ilkesi).

Yalnızca Python standart kütüphanesi kullanır.
"""

import re
import urllib.parse

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_PAYLOAD_LENGTH = 2048
MAX_SLEEP_SECONDS = 5
MAX_BENCHMARK_ITERATIONS = 1000000

# Kullanıcı bilgisi (user@host), ters bölü, boşluk ve kontrol karakterleri; URL ayrıştırıcıları
# arasındaki farklarla kapsam atlatmak için kullanılabilir → bu tür netloc'lar reddedilir.
_NETLOC_FORBIDDEN = re.compile(r"[\s\\@\x00-\x1f\x7f]")


def normalize_origin(url):
    """URL'yi (scheme, host, port) üçlüsüne indirger. Geçersiz/şüpheli URL'de None döner."""
    if not isinstance(url, str):
        return None
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        return None
    netloc = parts.netloc or ""
    if not netloc or _NETLOC_FORBIDDEN.search(netloc):
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError:
        return None
    return (scheme, host, port)


def is_in_scope(url, scope_url):
    """url, scope_url ile aynı köken (scheme + host + port) mü?"""
    origin = normalize_origin(url)
    return origin is not None and origin == normalize_origin(scope_url)


_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)

_BLOCK_RULES = [
    ("yıkıcı SQL (şema değiştirme)", re.compile(
        r"\b(?:drop|truncate|alter|create|rename)\s{1,10}(?:table|database|schema|index|view|user|role|"
        r"function|procedure|trigger|sequence)\b", re.I)),
    ("yıkıcı SQL (veri değiştirme)", re.compile(
        r"\b(?:delete\s{1,10}from|insert\s{1,10}into|replace\s{1,10}into|merge\s{1,10}into|"
        r"update\s{1,10}[\w\x60\"\[\].]{1,128}\s{1,10}set)\b", re.I)),
    ("SQL yetki / sistem komutu", re.compile(
        r"\b(?:grant|revoke)\s{1,10}(?:all|select|insert|update|delete|execute|usage)\b|\bxp_cmdshell\b|"
        r"\bsp_configure\b|\bsp_oacreate\b", re.I)),
    ("dosyaya yazma / program çalıştırma", re.compile(
        r"\binto\s{1,10}(?:out|dump)file\b|\bcopy\s[^;]{1,200}?\s(?:to|from)\s{1,10}program\b|"
        r"\blo_export\b|\bload_extension\s*\(", re.I)),
    ("yıkıcı işletim sistemi komutu", re.compile(
        r"\brm\s{1,5}-[a-z]{0,5}[rf][a-z]{0,5}\b"
        r"|\bmkfs(?:\.\w{1,10})?\b"
        r"|\bdd\s{1,5}if="
        r"|(?:^|[;&|\x60$(\n]\s{0,5})(?:sudo\s{1,5})?(?:shutdown|reboot|halt|poweroff)\b"
        r"|\b(?:shutdown|reboot|halt|poweroff)\s{1,5}(?:-[a-z]{1,5}|now)\b"
        r"|\binit\s{1,5}[06]\b"
        r"|:\(\)\s{0,5}\{\s{0,5}:\s{0,5}\|\s{0,5}:\s{0,5}&\s{0,5}\}"
        r"|\bchmod\s{1,5}(?:-R\s{1,5})?[0-7]{3,4}\s{1,5}/(?:\s|$)"
        r"|\b(?:killall|pkill)\b"
        r"|>\s{0,5}/dev/sd[a-z]"
        r"|\bdel\s{1,5}/[sfq]\b|\brd\s{1,5}/s\b|\bformat\s{1,5}[a-z]:", re.I)),
    ("uzaktan kod indirme / ters kabuk", re.compile(
        r"\b(?:curl|wget)\b[^|;&]{0,300}\|\s{0,5}(?:ba|z|k|da)?sh\b"
        r"|\b(?:nc|ncat|netcat)\b[^|;&]{0,100}\s-[a-z]{0,3}[ec]\b"
        r"|/dev/tcp/|\bbash\s{1,5}-i\b"
        r"|\bpowershell\b[^\n]{0,200}-(?:enc|encodedcommand)\b"
        r"|\bpython[23]?\s{1,5}-c\s[^\n]{0,200}socket", re.I)),
    ("bulut metadata / kimlik bilgisi uç noktası", re.compile(
        r"169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|metadata\.azure\.com|"
        r"100\.100\.100\.200|fd00:ec2::254", re.I)),
]

_SLEEP_CALL = re.compile(r"\b(?:sleep|pg_sleep|dbms_lock\.sleep|dbms_session\.sleep)\s*\(\s*(\d{1,9}(?:\.\d{1,6})?)", re.I)
_SHELL_SLEEP = re.compile(r"(?:^|[;&|\x60$(\s])sleep\s{1,5}(\d{1,9}(?:\.\d{1,6})?)", re.I)
_WAITFOR = re.compile(r"waitfor\s{1,10}delay\s{1,10}'(\d{1,2}):(\d{1,2}):(\d{1,2})", re.I)
_BENCHMARK = re.compile(r"\bbenchmark\s*\(\s*(\d{1,15})", re.I)


def _variants(text):
    """Ham, URL-çözülmüş (2 kata kadar) ve SQL yorumu temizlenmiş varyantlar."""
    out = {text}
    cur = text
    for _ in range(2):
        try:
            nxt = urllib.parse.unquote_plus(cur)
        except Exception:
            break
        if nxt == cur:
            break
        out.add(nxt)
        cur = nxt
    return out | {_SQL_COMMENT.sub(" ", v) for v in out}


def validate_probe_payload(payload, max_length=MAX_PAYLOAD_LENGTH):
    """(izinli_mi, gerekçe) döner.

    Salt-okunur, kısa ve kimlik bilgisi uç noktalarını hedeflemeyen payload'lara izin verir.
    XSS işaretleri, tırnak/boolean SQLi, kısa (≤5 sn) zaman gecikmesi, SSTI ve yol geçişi
    gibi kanıt üreten problar serbesttir.
    """
    if payload is None:
        return True, ""
    text = str(payload)
    if max_length and len(text) > max_length:
        return False, "payload çok uzun (%d > %d karakter)" % (len(text), max_length)
    for variant in _variants(text):
        for label, rx in _BLOCK_RULES:
            if rx.search(variant):
                return False, label
        for m in _SLEEP_CALL.finditer(variant):
            if float(m.group(1)) > MAX_SLEEP_SECONDS:
                return False, "uzun süreli gecikme (hizmet aksatma riski)"
        for m in _SHELL_SLEEP.finditer(variant):
            if float(m.group(1)) > MAX_SLEEP_SECONDS:
                return False, "uzun süreli gecikme (hizmet aksatma riski)"
        for m in _WAITFOR.finditer(variant):
            hours, minutes, seconds = (int(x) for x in m.groups())
            if hours * 3600 + minutes * 60 + seconds > MAX_SLEEP_SECONDS:
                return False, "uzun süreli gecikme (hizmet aksatma riski)"
        for m in _BENCHMARK.finditer(variant):
            if int(m.group(1)) > MAX_BENCHMARK_ITERATIONS:
                return False, "yüksek maliyetli BENCHMARK (hizmet aksatma riski)"
    return True, ""
