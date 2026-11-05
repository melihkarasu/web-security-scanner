#!/usr/bin/env python3
"""
updater.py — GitHub Sürüm Karşılaştırma ve Tek Tıkla Arayüzden Canlı Güncelleme Motoru.

Özellikler:
  - Hem yerel Git kurulumunda (.git mevcut) hem de Docker konteynerinde (.git yok) çalışır.
  - Git blob SHA-1 (sha1("blob <boyut>\0<içerik>")) hesaplayarak yerel uygulama dosyalarını
    GitHub main dalındaki ağaç (tree) ile birebir karşılaştırır.
  - Arayüzden "Şimdi Güncelle" tıklandığında GitHub main arşivini güvenli biçimde indirir,
    uygulama dosyalarını günceller, Docker kalıcı birimine (/app/data/live_update) yazar
    ve sunucu sürecini (PID 1 dahil) yerinde yeniden başlatır (os.execv).
"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request

GITHUB_REPO = os.environ.get("WSS_GITHUB_REPO", "melihkarasu/web-security-scanner")
GITHUB_BRANCH = os.environ.get("WSS_GITHUB_BRANCH", "main")
CHECK_CACHE_TTL = 60  # saniye

TRACKED_CORE_FILES = (
    "server.py",
    "index.html",
    "js/app.js",
    "css/style.css",
    "sast_engine.py",
    "active_scan_engine.py",
    "headless_browser.py",
    "strix_engine.py",
    "ai_orchestrator.py",
    "ai_connector.py",
    "updater.py",
)

UPDATABLE_EXTENSIONS = (".py", ".html", ".js", ".css", ".md", ".sh", ".json", ".txt", ".yml", ".yaml")
PROTECTED_PATHS = frozenset({".env", "data", "strix_scans", "__pycache__", ".git"})

_CACHE_LOCK = threading.Lock()
_CHECK_CACHE = {"at": 0.0, "data": None}


def git_blob_sha1(file_path):
    """Dosyanın standart Git blob SHA-1 özetini hesaplar (.git klasörü gerekmez)."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        header = ("blob %d\0" % len(data)).encode("ascii")
        return hashlib.sha1(header + data).hexdigest()
    except OSError:
        return ""


def _meta_file_path(app_dir, data_dir=None):
    base = data_dir or os.path.join(app_dir, "data")
    return os.path.join(base, "live_update", "meta.json")


def local_commit_info(app_dir, data_dir=None):
    """Yerel commit SHA bilgisi: önce live_update meta.json, sonra git rev-parse HEAD."""
    meta_path = _meta_file_path(app_dir, data_dir)
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if isinstance(meta, dict) and meta.get("commit"):
                return str(meta["commit"]), str(meta.get("updated_at") or "")
        except Exception:
            pass
    git_dir = os.path.join(app_dir, ".git")
    if os.path.exists(git_dir):
        try:
            out = subprocess.run(
                ["git", "-C", app_dir, "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=3, stdin=subprocess.DEVNULL
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip(), ""
        except Exception:
            pass
    return "", ""


def _github_get_json(url, timeout=10):
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "WebSecurityScanner-Updater/2.0",
        },
    )
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_for_updates(app_dir, data_dir=None, force=False):
    """GitHub main dalındaki son sürüm ile yerel dosyaları (Git blob SHA-1) karşılaştırır."""
    now = time.time()
    with _CACHE_LOCK:
        if not force and _CHECK_CACHE["data"] and (now - _CHECK_CACHE["at"] < CHECK_CACHE_TTL):
            return dict(_CHECK_CACHE["data"])

    local_sha, updated_at = local_commit_info(app_dir, data_dir)
    local_blobs = {}
    for rel in TRACKED_CORE_FILES:
        full = os.path.join(app_dir, rel)
        if os.path.isfile(full):
            local_blobs[rel] = git_blob_sha1(full)

    commit_url = "https://api.github.com/repos/%s/commits/%s" % (GITHUB_REPO, GITHUB_BRANCH)
    try:
        commit_data = _github_get_json(commit_url, timeout=10)
        remote_sha = str(commit_data.get("sha") or "")
        commit_obj = commit_data.get("commit") or {}
        raw_msg = str(commit_obj.get("message") or "").strip()
        latest_msg = raw_msg.splitlines()[0] if raw_msg else ""
        committer = commit_obj.get("committer") or commit_obj.get("author") or {}
        latest_date = str(committer.get("date") or "")
        tree_sha = str((commit_obj.get("tree") or {}).get("sha") or GITHUB_BRANCH)

        tree_url = "https://api.github.com/repos/%s/git/trees/%s?recursive=1" % (GITHUB_REPO, tree_sha)
        tree_data = _github_get_json(tree_url, timeout=10)
        remote_blobs = {}
        for item in (tree_data.get("tree") or []):
            if isinstance(item, dict) and item.get("type") == "blob":
                remote_blobs[item.get("path")] = item.get("sha")

        changed_files = []
        for rel in TRACKED_CORE_FILES:
            r_sha = remote_blobs.get(rel)
            l_sha = local_blobs.get(rel)
            if r_sha and l_sha != r_sha:
                changed_files.append(rel)

        update_available = bool(changed_files)
        effective_local_sha = remote_sha if (not update_available and remote_sha) else local_sha

        result = {
            "ok": True,
            "repo": GITHUB_REPO,
            "branch": GITHUB_BRANCH,
            "update_available": update_available,
            "up_to_date": not update_available,
            "current_commit": effective_local_sha[:7] if effective_local_sha else "yerel",
            "current_commit_full": effective_local_sha,
            "latest_commit": remote_sha[:7] if remote_sha else "",
            "latest_commit_full": remote_sha,
            "latest_message": latest_msg,
            "latest_date": latest_date,
            "changed_files": changed_files,
            "changed_count": len(changed_files),
            "can_self_update": os.access(app_dir, os.W_OK),
            "in_docker": os.path.exists("/.dockerenv"),
            "release_url": "https://github.com/%s/commits/%s" % (GITHUB_REPO, GITHUB_BRANCH),
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except Exception as e:
        result = {
            "ok": False,
            "repo": GITHUB_REPO,
            "branch": GITHUB_BRANCH,
            "update_available": False,
            "up_to_date": True,
            "current_commit": local_sha[:7] if local_sha else "yerel",
            "error": "GitHub sürüm kontrolü yapılamadı: %s" % str(e)[:160],
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    with _CACHE_LOCK:
        _CHECK_CACHE["at"] = now
        _CHECK_CACHE["data"] = dict(result)
    return result


def _is_safe_relpath(rel_path):
    if not rel_path or rel_path.startswith("/") or ".." in rel_path.split("/"):
        return False
    top = rel_path.split("/")[0]
    if top in PROTECTED_PATHS:
        return False
    return rel_path.endswith(UPDATABLE_EXTENSIONS) or rel_path in ("Dockerfile", "Dockerfile.browser", "LICENSE")


def apply_update(app_dir, data_dir=None):
    """GitHub main arşivini indirir, uygulama dosyalarını günceller ve kalıcı önbelleğe yazar."""
    if not os.access(app_dir, os.W_OK):
        return {"ok": False, "error": "Uygulama dizini (%s) yazılabilir değil." % app_dir}

    # Önce güncel commit bilgisini al
    info = check_for_updates(app_dir, data_dir=data_dir, force=True)
    latest_sha = info.get("latest_commit_full") or ""
    latest_msg = info.get("latest_message") or ""

    tar_url = "https://codeload.github.com/%s/tar.gz/refs/heads/%s" % (GITHUB_REPO, GITHUB_BRANCH)
    req = urllib.request.Request(tar_url, headers={"User-Agent": "WebSecurityScanner-Updater/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw_tar = resp.read()
    except Exception as e:
        return {"ok": False, "error": "GitHub güncelleme paketi indirilemedi: %s" % str(e)[:180]}

    updated_files = []
    persist_root = os.path.join(data_dir or os.path.join(app_dir, "data"), "live_update")
    persist_files_dir = os.path.join(persist_root, "files")

    try:
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                parts = member.name.split("/", 1)
                if len(parts) < 2:
                    continue
                rel_path = parts[1].strip("/")
                if not _is_safe_relpath(rel_path):
                    continue
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                new_bytes = fobj.read()
                dest_path = os.path.join(app_dir, rel_path)
                os.makedirs(os.path.dirname(dest_path) or app_dir, exist_ok=True)

                old_bytes = None
                if os.path.isfile(dest_path):
                    try:
                        with open(dest_path, "rb") as cur_f:
                            old_bytes = cur_f.read()
                    except OSError:
                        pass

                if old_bytes != new_bytes:
                    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(dest_path) or app_dir)
                    with os.fdopen(tmp_fd, "wb") as out_f:
                        out_f.write(new_bytes)
                    if rel_path.endswith(".sh"):
                        os.chmod(tmp_path, 0o755)
                    else:
                        os.chmod(tmp_path, 0o644)
                    os.replace(tmp_path, dest_path)
                    updated_files.append(rel_path)

                # Docker kalıcı birimine de yedekle (konteyner yeniden başlatılırsa korunur)
                try:
                    p_dest = os.path.join(persist_files_dir, rel_path)
                    os.makedirs(os.path.dirname(p_dest), exist_ok=True)
                    with open(p_dest, "wb") as pf:
                        pf.write(new_bytes)
                except OSError:
                    pass

        # Eğer yerel .git deposu varsa referansı da senkronize et (hata verirse yoksay)
        if os.path.isdir(os.path.join(app_dir, ".git")):
            try:
                subprocess.run(
                    ["git", "-C", app_dir, "fetch", "origin", GITHUB_BRANCH],
                    capture_output=True, timeout=10, stdin=subprocess.DEVNULL
                )
            except Exception:
                pass

        meta = {
            "commit": latest_sha,
            "message": latest_msg,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "updated_files": updated_files,
        }
        try:
            os.makedirs(persist_root, exist_ok=True)
            with open(os.path.join(persist_root, "meta.json"), "w", encoding="utf-8") as mf:
                json.dump(meta, mf, ensure_ascii=False, indent=2)
        except OSError:
            pass

        with _CACHE_LOCK:
            _CHECK_CACHE["at"] = 0.0
            _CHECK_CACHE["data"] = None

        return {
            "ok": True,
            "updated_files": updated_files,
            "updated_count": len(updated_files),
            "latest_commit": latest_sha[:7] if latest_sha else "",
            "latest_commit_full": latest_sha,
            "latest_message": latest_msg,
            "restarting": True,
        }
    except Exception as e:
        return {"ok": False, "error": "Güncelleme uygulanırken hata oluştu: %s" % str(e)[:180]}


def restore_persisted_update(app_dir, data_dir=None):
    """Docker konteyneri yeniden başladığında /app/data/live_update içindeki güncel dosyaları geri yükler."""
    persist_root = os.path.join(data_dir or os.path.join(app_dir, "data"), "live_update")
    meta_path = os.path.join(persist_root, "meta.json")
    files_dir = os.path.join(persist_root, "files")
    if not (os.path.isfile(meta_path) and os.path.isdir(files_dir)):
        return 0
    restored = 0
    for root, _dirs, files in os.walk(files_dir):
        for fname in files:
            src_path = os.path.join(root, fname)
            rel_path = os.path.relpath(src_path, files_dir).replace("\\", "/")
            if not _is_safe_relpath(rel_path):
                continue
            dest_path = os.path.join(app_dir, rel_path)
            try:
                with open(src_path, "rb") as sf:
                    s_bytes = sf.read()
                d_bytes = None
                if os.path.isfile(dest_path):
                    with open(dest_path, "rb") as df:
                        d_bytes = df.read()
                if s_bytes != d_bytes:
                    os.makedirs(os.path.dirname(dest_path) or app_dir, exist_ok=True)
                    with open(dest_path, "wb") as df:
                        df.write(s_bytes)
                    restored += 1
            except OSError:
                pass
    return restored
