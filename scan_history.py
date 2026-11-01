#!/usr/bin/env python3
"""
scan_history.py — Tarama geçmişi ve önceki taramaya göre fark raporu (Faz 3).

PentAGI'nin kalıcı depolamasının (PostgreSQL) bu araca uyarlanmış, yalnızca Python standart
kütüphanesi (sqlite3) kullanan hâli:
  - Her aktif / AI taraması hedef kökeni (scheme://host:port) bazında kaydedilir.
  - Bulgular kararlı bir parmak iziyle saklanır; aynı hedef + aynı tür için önceki taramaya
    göre fark üretilir: yeni / kapanan (bu taramada görülmeyen) / devam eden.
  - AI bulgularının başlığı LLM gerekçesi içerdiği için parmak izi başlıktan değil
    (zafiyet sınıfı + yol + parametre + CWE) üzerinden hesaplanır.
  - Gizli bilgiler kaydetmeden önce maskelenir (redaction.redact_obj).
  - Saklama süresi varsayılan 30 gün (WSS_HISTORY_RETENTION_DAYS); WSS_HISTORY=0 kaydı kapatır.
  - Veritabanı yerel dosyadır (WSS_HISTORY_DB veya <uygulama>/data/scan_history.sqlite3);
    dizin 0700, dosya 0600 izinle oluşturulur. Dışarıya hiçbir veri gönderilmez.
"""

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse
import uuid

from redaction import redact_obj, redact_text
from safety_guard import normalize_origin

APP_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_SCANS = 500
MAX_FINDINGS_PER_SCAN = 500
MAX_EVIDENCE_CHARS = 300

_MEMORY_CACHE = {}
_MEMORY_LOCK = threading.Lock()

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS scans ("
    " id TEXT PRIMARY KEY, target TEXT NOT NULL, target_key TEXT NOT NULL, kind TEXT NOT NULL,"
    " created_at INTEGER NOT NULL, summary_json TEXT NOT NULL, findings_json TEXT NOT NULL,"
    " meta_json TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_key, kind, created_at)",
    "CREATE TABLE IF NOT EXISTS intel_cache (key TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL,"
    " payload TEXT NOT NULL)",
)


def history_enabled():
    return os.environ.get("WSS_HISTORY", "1").strip().lower() not in ("0", "false", "no", "off")


def db_path():
    custom = os.environ.get("WSS_HISTORY_DB", "").strip()
    return custom or os.path.join(APP_DIR, "data", "scan_history.sqlite3")


def retention_days():
    try:
        return max(1, min(365, int(os.environ.get("WSS_HISTORY_RETENTION_DAYS", "30"))))
    except ValueError:
        return 30


def _connect():
    path = db_path()
    directory = os.path.dirname(path) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    for stmt in _SCHEMA:
        conn.execute(stmt)
    conn.commit()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return conn


def target_key(url):
    origin = normalize_origin(str(url or ""))
    if origin:
        return "%s://%s:%d" % origin
    return str(url or "").strip().lower()[:200]


# ---------------------------------------------------------------- parmak izi
_DIGITS = re.compile(r"\d+")
_SPACES = re.compile(r"\s+")
_AI_TITLE = re.compile(r"^\[AI-[^\]]*\]\s*([A-Za-z0-9_ -]{1,40}?)\s+—")
_PARAM_IN_TITLE = re.compile(r"param=([\w.\-\[\]]{1,60})")


def _norm(text, limit=160):
    return _SPACES.sub(" ", _DIGITS.sub("#", str(text or "").lower())).strip()[:limit]


def _location(finding):
    url = str(finding.get("url") or "")
    if not url:
        summary = str(finding.get("summary") or "")
        if summary.startswith(("http://", "https://")):
            url = summary.split(" ", 1)[0]
    if not url:
        return ""
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except ValueError:
        return ""


def finding_fingerprint(finding):
    title = str(finding.get("title") or "")
    param = str(finding.get("param") or "")
    if not param:
        m = _PARAM_IN_TITLE.search(title)
        if m:
            param = m.group(1)
    cwe = str(finding.get("cwe") or "").upper()
    ai = _AI_TITLE.match(title)
    if ai:
        basis = ["ai", ai.group(1).strip().lower(), _location(finding), param, cwe]
    else:
        basis = ["std", _norm(finding.get("test")), _norm(title), _location(finding), param, cwe]
    return hashlib.sha256("|".join(basis).encode("utf-8")).hexdigest()[:16]


def _slim(finding):
    return {
        "fp": finding_fingerprint(finding),
        "test": str(finding.get("test") or "")[:120],
        "title": str(finding.get("title") or "")[:240],
        "severity": str(finding.get("severity") or "")[:20],
        "cwe": str(finding.get("cwe") or "")[:40],
        "verdict": str(finding.get("verdict") or finding.get("lifecycle") or "")[:40],
        "location": _location(finding)[:200],
        "evidence": str(finding.get("evidence") or "")[:MAX_EVIDENCE_CHARS],
    }


# ---------------------------------------------------------------- kayıt / okuma
def record_scan(kind, target_url, findings, summary=None, meta=None):
    """Taramayı kaydeder ve önceki taramaya göre kısa fark özetini döndürür (kapalıysa None)."""
    if not history_enabled():
        return None
    slim, seen = [], set()
    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        item = _slim(f)
        if item["fp"] in seen:
            continue
        seen.add(item["fp"])
        slim.append(item)
        if len(slim) >= MAX_FINDINGS_PER_SCAN:
            break
    slim = redact_obj(slim)
    by_sev = {}
    for item in slim:
        by_sev[item["severity"] or "?"] = by_sev.get(item["severity"] or "?", 0) + 1
    summ = dict(summary or {})
    summ.update({"finding_count": len(slim), "by_severity": by_sev})
    scan_id = uuid.uuid4().hex
    created = int(time.time())
    tkey = target_key(target_url)
    conn = _connect()
    try:
        with conn:
            conn.execute(
                "INSERT INTO scans (id, target, target_key, kind, created_at, summary_json, findings_json, meta_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, redact_text(str(target_url or ""))[:500], tkey, str(kind or "scan")[:20], created,
                 json.dumps(redact_obj(summ), ensure_ascii=False, default=str),
                 json.dumps(slim, ensure_ascii=False),
                 json.dumps(redact_obj(meta or {}), ensure_ascii=False, default=str)))
    finally:
        conn.close()
    prune()
    return {"scan_id": scan_id, "created_at": created, "target_key": tkey, "kind": kind,
            "retention_days": retention_days(), "diff": diff_brief(diff_scans(scan_id))}


def _row_to_scan(row, with_findings=True):
    out = {"id": row["id"], "rowid": row["rowid"], "target": row["target"], "target_key": row["target_key"],
           "kind": row["kind"], "created_at": row["created_at"], "summary": json.loads(row["summary_json"] or "{}")}
    if with_findings:
        out["findings"] = json.loads(row["findings_json"] or "[]")
        out["meta"] = json.loads(row["meta_json"] or "{}")
    return out


def get_scan(scan_id):
    if not history_enabled() or not scan_id:
        return None
    conn = _connect()
    try:
        row = conn.execute("SELECT rowid, * FROM scans WHERE id = ?", (str(scan_id),)).fetchone()
    finally:
        conn.close()
    return _row_to_scan(row) if row else None


def list_scans(target=None, kind=None, limit=50):
    if not history_enabled():
        return []
    sql = "SELECT rowid, id, target, target_key, kind, created_at, summary_json FROM scans"
    where, args = [], []
    if target:
        where.append("target_key = ?")
        args.append(target_key(target))
    if kind:
        where.append("kind = ?")
        args.append(str(kind))
    if where:
        sql += " WHERE " + " AND ".join(where)
    try:
        lim = max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        lim = 50
    sql += " ORDER BY rowid DESC LIMIT ?"
    args.append(lim)
    conn = _connect()
    try:
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    return [_row_to_scan(r, with_findings=False) for r in rows]


def _previous_scan(scan):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id FROM scans WHERE target_key = ? AND kind = ? AND rowid < ? ORDER BY rowid DESC LIMIT 1",
            (scan["target_key"], scan["kind"], scan["rowid"])).fetchone()
    finally:
        conn.close()
    return get_scan(row["id"]) if row else None


def diff_scans(scan_id, base_id=None):
    """Tam fark: yeni / kapanan (bu taramada görülmeyen) / devam eden bulgular."""
    new = get_scan(scan_id)
    if not new:
        return None
    base = get_scan(base_id) if base_id else _previous_scan(new)
    new_map = {f["fp"]: f for f in new["findings"]}
    if not base:
        return {"scan_id": new["id"], "base_scan_id": None, "base_created_at": None, "first_scan": True,
                "new": list(new_map.values()), "fixed": [], "persisting": []}
    base_map = {f["fp"]: f for f in base["findings"]}
    return {"scan_id": new["id"], "base_scan_id": base["id"], "base_created_at": base["created_at"],
            "first_scan": False,
            "new": [f for fp, f in new_map.items() if fp not in base_map],
            "fixed": [f for fp, f in base_map.items() if fp not in new_map],
            "persisting": [f for fp, f in new_map.items() if fp in base_map]}


def diff_brief(diff, limit=8):
    if not diff:
        return None

    def brief(items):
        return [{"title": f.get("title", ""), "severity": f.get("severity", "")} for f in items[:limit]]
    return {"base_scan_id": diff["base_scan_id"], "base_created_at": diff["base_created_at"],
            "first_scan": diff["first_scan"],
            "counts": {"new": len(diff["new"]), "fixed": len(diff["fixed"]), "persisting": len(diff["persisting"])},
            "new": brief(diff["new"]), "fixed": brief(diff["fixed"])}


# ---------------------------------------------------------------- silme / saklama
def _delete(sql, args):
    if not history_enabled():
        return 0
    conn = _connect()
    try:
        with conn:
            return conn.execute(sql, args).rowcount
    finally:
        conn.close()


def delete_scan(scan_id):
    return _delete("DELETE FROM scans WHERE id = ?", (str(scan_id or ""),))


def delete_target(target):
    return _delete("DELETE FROM scans WHERE target_key = ?", (target_key(target),))


def delete_all():
    return _delete("DELETE FROM scans", ())


def prune():
    """Saklama süresi dolan ve MAX_SCANS sınırını aşan en eski kayıtları siler."""
    if not history_enabled():
        return 0
    cutoff = int(time.time()) - retention_days() * 86400
    conn = _connect()
    try:
        with conn:
            removed = conn.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,)).rowcount
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            if total > MAX_SCANS:
                removed += conn.execute(
                    "DELETE FROM scans WHERE rowid IN (SELECT rowid FROM scans ORDER BY rowid ASC LIMIT ?)",
                    (total - MAX_SCANS,)).rowcount
        return removed
    finally:
        conn.close()


# ---------------------------------------------------------------- tehdit istihbaratı önbelleği
def cache_get(key, max_age_seconds):
    """Herkese açık zafiyet verisi için önbellek (geçmiş kapalıysa bellekte tutulur)."""
    now = int(time.time())
    if not history_enabled():
        with _MEMORY_LOCK:
            hit = _MEMORY_CACHE.get(key)
        return hit[1] if hit and now - hit[0] <= max_age_seconds else None
    conn = _connect()
    try:
        row = conn.execute("SELECT fetched_at, payload FROM intel_cache WHERE key = ?", (str(key),)).fetchone()
    finally:
        conn.close()
    if not row or now - row["fetched_at"] > max_age_seconds:
        return None
    try:
        return json.loads(row["payload"])
    except ValueError:
        return None


def cache_set(key, payload):
    now = int(time.time())
    if not history_enabled():
        with _MEMORY_LOCK:
            _MEMORY_CACHE[key] = (now, payload)
        return
    conn = _connect()
    try:
        with conn:
            conn.execute("INSERT OR REPLACE INTO intel_cache (key, fetched_at, payload) VALUES (?, ?, ?)",
                         (str(key), now, json.dumps(payload, ensure_ascii=False, default=str)))
    finally:
        conn.close()
