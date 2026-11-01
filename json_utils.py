#!/usr/bin/env python3
"""
json_utils.py — LLM ciktisindan saglam JSON cikarimi (deterministik onarim dahil).

PentAGI'nin "tool_call_fixer / bozuk JSON onarimi" yaklasiminin bu araca uyarlanmis,
yalnizca Python standart kutuphanesi kullanan hali. Bir LLM yanitindan ilk dengeli JSON
dizisini/nesnesini cikarir; dogrudan ayristirma basarisiz olursa yaygin bozulmalari
(```json citleri, sondaki virguller, akilli tirnaklar, bastaki/sondaki gurultu)
deterministik olarak onarip yeniden dener. Ag ya da ikinci bir LLM cagrisi yapmaz.
"""

import json
import re

ERROR_PREFIXES = ("Error:", "error:", "ERROR:")

_FENCE = re.compile(r"```(?:json|javascript|js)?\s*(.*?)\s*```", re.S | re.I)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")
_SMART = {
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"',
    "\u2018": "'", "\u2019": "'", "\u00ab": '"', "\u00bb": '"',
    "\u2013": "-", "\u2014": "-", "\u00a0": " ",
}


def looks_like_error(text):
    """Baglayicidan donen metin bir hata/bos yanit mi?"""
    t = (text or "").strip()
    return (not t) or t.startswith(ERROR_PREFIXES) or len(t) < 3


def _strip_smart(text):
    for bad, good in _SMART.items():
        text = text.replace(bad, good)
    return text


def _balanced_block(text, opener, closer):
    """Ilk dengeli opener..closer blogunu (string/kacis farkinda) dondurur."""
    start = text.find(opener)
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _try_loads(block):
    if block is None:
        return None, False
    try:
        return json.loads(block), False
    except Exception:
        pass
    repaired = _TRAILING_COMMA.sub(r"\1", _strip_smart(block))
    try:
        return json.loads(repaired), True
    except Exception:
        return None, False


def extract_json(text, want="object"):
    """LLM ciktisindan istenen turde (object|list) ilk gecerli JSON'u cikarir; yoksa None."""
    text = text or ""
    fence = _FENCE.search(text)
    candidates = []
    if fence:
        candidates.append(fence.group(1))
    candidates.append(text)
    opener, closer = ("[", "]") if want == "list" else ("{", "}")
    for cand in candidates:
        parsed, _ = _try_loads(_balanced_block(cand, opener, closer))
        if parsed is not None:
            return parsed
    if want == "list":
        parsed, _ = _try_loads(_balanced_block(text, "{", "}"))
        if isinstance(parsed, dict):
            for v in parsed.values():
                if isinstance(v, list):
                    return v
    return None


def extract_json_detail(text, want="object"):
    """extract_json ile ayni ama (parsed, repaired) dondurur; onarim yapildiysa repaired=True."""
    text = text or ""
    fence = _FENCE.search(text)
    candidates = [fence.group(1)] if fence else []
    candidates.append(text)
    opener, closer = ("[", "]") if want == "list" else ("{", "}")
    for cand in candidates:
        parsed, repaired = _try_loads(_balanced_block(cand, opener, closer))
        if parsed is not None:
            return parsed, (repaired or bool(fence))
    if want == "list":
        parsed, repaired = _try_loads(_balanced_block(text, "{", "}"))
        if isinstance(parsed, dict):
            for v in parsed.values():
                if isinstance(v, list):
                    return v, True
    return None, False
