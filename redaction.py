#!/usr/bin/env python3
"""
redaction.py — LLM'e giden metinlerde gizli bilgi maskeleme.

PentAGI kendi kimlik bilgilerini log ve ajan kayıtlarından maskeler (GetSecretPatterns).
Bu araçta bulut/yerel LLM'e hedeften gelen veri (başlıklar, çerezler, yanıt gövdeleri) ve
SAST AI denetiminde kaynak kod gider. Bu modül bunları LLM'e gitmeden önce maskeler;
analiz için gereken yapı korunur:
  - JWT'nin header kısmı (alg/typ) korunur; payload ve imza maskelenir.
  - Çerez adları ve öznitelikleri (Path, HttpOnly, Secure, SameSite ...) korunur; değerler maskelenir.
  - Koddaki sabit (hardcoded) sırlar "[REDACTED]" ile değiştirilir; "burada sabit bir sır var"
    bilgisi LLM'e kalır. Ortam değişkeninden okunan değerler (os.environ.get(...)) dokunulmaz.

Yalnızca Python standart kütüphanesi kullanır. Desenler sınırlı niceleyicilerle yazılmıştır;
uzun girdilerde felaket geri izleme (catastrophic backtracking) oluşmaz.
"""

import re

MASK = "[REDACTED]"

_COOKIE_ATTRS = frozenset((
    "path", "domain", "expires", "max-age", "samesite", "secure", "httponly",
    "priority", "partitioned", "version", "comment",
))
_COOKIE_PAIR = re.compile(r"(^|[;,]\s*)([^=;,\s]{1,128})=([^;,]*)")


def _mask_cookie_value(value):
    """'a=1; Path=/; HttpOnly, b=2' → 'a=[REDACTED]; Path=/; HttpOnly, b=[REDACTED]'"""
    def repl(m):
        lead, name, val = m.group(1), m.group(2), m.group(3)
        if name.lower() in _COOKIE_ATTRS or not val.strip():
            return m.group(0)
        return "%s%s=%s" % (lead, name, MASK)
    return _COOKIE_PAIR.sub(repl, value)


def _mask_jwt(m):
    return "%s.[REDACTED_JWT_PAYLOAD].%s" % (m.group(1), "[REDACTED_JWT_SIGNATURE]" if m.group(3) else "")


def _mask_authorization(m):
    scheme = m.group(3)
    return "%s%s%s%s" % (m.group(1), m.group(2), (scheme + " ") if scheme else "", MASK)


def _mask_cookie_header(m):
    return m.group(1) + m.group(2) + _mask_cookie_value(m.group(3))


_SENSITIVE_WORD = (
    r"(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|"
    r"client[_-]?secret|private[_-]?key|session[_-]?id|sessid|credential|bearer)"
)
_SENSITIVE_KEY = r"[\w.-]{0,40}?" + _SENSITIVE_WORD + r"s?[\w.-]{0,40}"

_RULES = [
    # 1) PEM özel anahtar blokları (tam blok, sonra kırpılmış/sonu olmayan blok)
    (re.compile(r"(-----BEGIN ([A-Z0-9 ]{0,30})PRIVATE KEY-----)[\s\S]{0,20000}?(-----END \2PRIVATE KEY-----)"),
     r"\1" + MASK + r"\3"),
    (re.compile(r"(-----BEGIN [A-Z0-9 ]{0,30}PRIVATE KEY-----)(?:\\n|\s|[A-Za-z0-9+/=]){16,}"),
     r"\1" + MASK),
    # 2) Authorization başlığı (JWT değilse; JWT ise alg korunarak aşağıda maskelenir)
    (re.compile(r"(?i)\b((?:proxy-)?authorization)([\"']?\s{0,5}[:=]\s{0,5}[\"']?)"
                r"(?:(bearer|basic|token|digest|negotiate|ntlm|apikey|api-key)\s{1,5})?"
                r"(?!eyJ[A-Za-z0-9_-]{4,}\.)([^\s\"',;]{1,4096})"),
     _mask_authorization),
    # 3) JWT: header (alg/typ) korunur, payload + imza maskelenir
    (re.compile(r"\b(eyJ[A-Za-z0-9_-]{4,2048})\.([A-Za-z0-9_-]{8,8192})\.([A-Za-z0-9_-]{0,2048})"), _mask_jwt),
    # 4) Cookie / Set-Cookie: adlar ve öznitelikler korunur, değerler maskelenir
    (re.compile(r"(?i)\b(set-cookie|cookie)([\"']?\s{0,5}[:=]\s{0,5}[\"']?)([^\r\n\"]{1,4096})"), _mask_cookie_header),
    # 5) Bilinen sağlayıcı anahtar biçimleri
    (re.compile(r"(?i)\b(aws_secret_access_key|aws_secret_key|secret_access_key)([\"']?\s{0,5}[:=]\s{0,5}[\"']?)"
                r"([A-Za-z0-9/+=]{40})"), r"\1\2" + MASK),
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|ABIA|ACCA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,64}"), "[REDACTED_GITLAB_TOKEN]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,255}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), "[REDACTED_GOOGLE_API_KEY]"),
    (re.compile(r"\bya29\.[0-9A-Za-z_-]{20,2048}"), "[REDACTED_GOOGLE_OAUTH_TOKEN]"),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,255}|\bwhsec_[0-9A-Za-z]{10,255}"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,255}"), "[REDACTED_ANTHROPIC_KEY]"),
    (re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\bhf_[A-Za-z0-9]{30,64}\b"), "[REDACTED_HF_TOKEN]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "[REDACTED_NPM_TOKEN]"),
    (re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{30,64}"), "[REDACTED_TELEGRAM_BOT_TOKEN]"),
    # 6) Bağlantı dizesindeki parola (postgres://kullanici:parola@host)
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://)([^:/@\s\"'<>]{1,256}):([^@/\s\"'<>]{1,256})@"),
     r"\1\2:" + MASK + "@"),
    # 7) Gizli form alanları (CSRF / nonce / token)
    (re.compile(r"(?i)(<input\b[^>]{0,400}?\bname=[\"'][^\"']{0,80}(?:csrf|xsrf|token|nonce|authenticity|verification)"
                r"[^\"']{0,80}[\"'][^>]{0,400}?\bvalue=)([\"'])([^\"']{6,512})\2"),
     r"\1\2" + MASK + r"\2"),
    # 8) URL sorgu parametreleri
    (re.compile(r"(?i)([?&](?:access_token|id_token|refresh_token|auth_token|token|api_key|apikey|key|secret|"
                r"client_secret|password|passwd|pwd|session|sessionid|sid|signature|sig|x-amz-signature|"
                r"x-amz-credential|x-amz-security-token|code)=)([^&#\s\"'<>]{4,512})"),
     r"\1" + MASK),
    # 9) Hassas adlı anahtara atanmış tırnaklı sabit (kod, JSON, YAML, PHP dizisi)
    (re.compile(r"(?i)(?<![\w.-])(" + _SENSITIVE_KEY + r")([\"']?\s{0,5}(?::|=>|=)\s{0,5})([\"'])([^\"'\r\n]{4,512}?)\3"),
     r"\1\2\3" + MASK + r"\3"),
    # 10) .env tarzı satırlar (BÜYÜK_HARF ad, tırnaksız değer, satır sonu)
    (re.compile(r"(?m)^([ \t]{0,8}(?:export[ \t]{1,4})?[A-Z0-9_]{0,40}(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|"
                r"APIKEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIALS?)[A-Z0-9_]{0,40}[ \t]{0,4}=[ \t]{0,4})"
                r"(?![\"'\[])([A-Za-z0-9+/=_\-.:@!#%^&*~]{4,512})(?=[ \t]*(?:#.*)?$)"),
     r"\1" + MASK),
]

_SENSITIVE_HEADER_NAMES = frozenset((
    "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "api-key", "apikey", "x-amz-security-token",
))
_SENSITIVE_KEY_RX = re.compile(r"(?i)^" + _SENSITIVE_KEY + r"$")


def redact_text(text):
    """Metindeki sırları maskeler. str olmayan ya da boş değerler aynen döner."""
    if not isinstance(text, str) or not text:
        return text
    for rx, repl in _RULES:
        text = rx.sub(repl, text)
    return text


def redact_obj(obj, _depth=0):
    """dict/list/str yapılarını özyinelemeli maskeler; orijinal nesneyi DEĞİŞTİRMEZ."""
    if _depth > 50:
        return obj
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out = {}
        for key, val in obj.items():
            lowered = str(key).lower()
            if isinstance(val, str) and lowered in ("cookie", "set-cookie"):
                out[key] = _mask_cookie_value(val)
            elif isinstance(val, str) and val and (lowered in _SENSITIVE_HEADER_NAMES or _SENSITIVE_KEY_RX.match(str(key))):
                out[key] = MASK
            else:
                out[key] = redact_obj(val, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_obj(x, _depth + 1) for x in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(x, _depth + 1) for x in obj)
    return obj
