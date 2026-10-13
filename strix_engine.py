#!/usr/bin/env python3
"""
Web Security Scanner — Strix Entegrasyon Motoru
================================================
Strix (açık kaynak otonom AI pentest aracı, https://github.com/usestrix/strix)
CLI'sını gerçek bir subprocess olarak yönetir:

- Kurulum/uygunluk tespiti (binary, docker sandbox imajı, sürüm, özellikler)
- Tarama başlatma: strix -t <hedef> -n -m <quick|standard|deep> ...
- Canlı durum: strix_runs/<run>/run.json + vulnerabilities.json dosyalarından
  bulgular bu uygulamanın bulgu şemasına (severity/CWE/CVSS/evidence/fix) çevrilir.
- İptal + günlük kuyruğu.

İlkeler:
- Etik onay geçidi üst katmanda (server.py) zorunludur; bu modül onay varsayar.
- STRIX_TELEMETRY=0: uzaktan telemetri kapatılır (uygulamanın "veri makineden
  çıkmaz" beyanıyla tutarlılık; LLM sağlayıcı çağrıları kullanıcı anahtarıyladır).
- Yalnızca Python 3 standart kütüphanesi.
"""

import json
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid

STRIX_MIN_VERSION = "1.0.0"

# Uygulama severitesi ← Strix severite eşlemesi
SEVERITY_MAP = {
    "critical": "KRİTİK",
    "high": "YÜKSEK",
    "medium": "ORTA",
    "low": "DÜŞÜK",
    "info": "BİLGİ",
}

SCAN_MODES = ("quick", "standard", "deep")

# Yapılandırılmış LLM → Strix (litellm) model/anahtar eşlemesi
# Strix şunları okur: STRIX_LLM, LLM_API_KEY|OPENAI_API_KEY, LLM_API_BASE|OPENAI_BASE_URL,
# OLLAMA_API_BASE, GOOGLE_APPLICATION_CREDENTIALS (service account için).
PROVIDER_MODEL_PREFIX = {
    "openai": "openai/",
    "openai_compatible": "openai/",
    "custom": "openai/",
    "gemini": "gemini/",
    "gemini_api": "gemini/",
    "google": "gemini/",
    "openrouter": "openrouter/",
    "ollama": "ollama_chat/",
    "vertex": "vertex_ai/",
}


def _which_strix():
    """Strix binary'sini çözümle: STRIX_BIN → PATH → repo-yerel/dev venv yedekleri."""
    env_bin = (os.environ.get("STRIX_BIN") or "").strip()
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    found = shutil.which("strix")
    if found:
        return found
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, ".venv-strix", "bin", "strix"),
        os.path.join(here, "..", "..", ".venv-strix", "bin", "strix"),
        os.path.expanduser("~/.venv-strix/bin/strix"),
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
    return None


def strix_capabilities():
    """Kurulum durumu + sürüm + docker sandbox imajı + desteklenen özellikler."""
    binary = _which_strix()
    caps = {
        "installed": binary is not None,
        "binary": binary,
        "version": None,
        "docker_available": False,
        "sandbox_image": None,
        "modes": list(SCAN_MODES),
        "features": [],
        "install_hint": "pip install strix-agent  (veya: pipx install strix-agent)",
    }
    if not binary:
        return caps

    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15)
        caps["version"] = (out.stdout or out.stderr).strip().splitlines()[0][-20:] if (out.stdout or out.stderr) else None
    except Exception:
        pass

    try:
        docker = shutil.which("docker")
        if docker:
            out = subprocess.run([docker, "images", "--format", "{{.Repository}}:{{.Tag}}"],
                                 capture_output=True, text=True, timeout=15)
            if out.returncode == 0:
                caps["docker_available"] = True
                for line in out.stdout.splitlines():
                    if "strix-sandbox" in line:
                        caps["sandbox_image"] = line.strip()
                        break
    except Exception:
        pass

    if caps["docker_available"] and caps["sandbox_image"]:
        caps["features"] = [
            "Otonom çoklu-ajan pentest (Scout/Exploit/Analyst topolojisi)",
            "Docker izole sandbox içinde gerçek istismar doğrulaması (PoC)",
            "OWASP Top 10 + iş mantığı zafiyetleri (IDOR, auth, race condition)",
            "CVSS 3.1 skorlama + CWE eşleme + kanıt tabanlı bulgular",
            "HTTP exchange kayıtları (istek/yanıt kanıtı)",
            "Zafiyet zincirleme korelasyonu",
            "Hızlı/standart/derin tarama modları",
        ]
    elif caps["docker_available"]:
        caps["features"] = ["Sandbox imajı henüz çekilmemiş: docker pull ghcr.io/usestrix/strix-sandbox"]
    return caps


def build_strix_env(ai_config: dict) -> dict:
    """UI'daki AI konfigürasyonunu Strix'in litellm ortam değişkenlerine çevirir."""
    env = dict(os.environ)
    env["STRIX_TELEMETRY"] = "0"  # beyan tutarlılığı: telemetri kapalı

    provider = (ai_config.get("provider") or "openai").lower().strip()
    model = (ai_config.get("model") or "").strip()
    auth = ai_config.get("auth") if isinstance(ai_config.get("auth"), dict) else {}
    key = (ai_config.get("api_key") or auth.get("value") or "").strip()
    base_url = (ai_config.get("base_url") or "").strip()
    prefix = PROVIDER_MODEL_PREFIX.get(provider, "openai/")

    if not model:
        raise ValueError("Strix için model adı gereklidir (örn: gpt-4o, gemini-3.5-flash, openrouter modeli).")

    env["STRIX_LLM"] = prefix + model

    if provider == "ollama":
        env["LLM_API_BASE"] = base_url or "http://localhost:11434"
        env["OLLAMA_API_BASE"] = env["LLM_API_BASE"]
        env["LLM_API_KEY"] = key or "ollama"  # litellm şema gereği dummy anahtar ister
    elif provider == "vertex":
        auth_type = (auth.get("type") or "api_key").lower()
        if auth_type == "service_account" and key:
            # Service account JSON içeriğini 0600 geçici dosyaya yaz (Strix ADC okur)
            import tempfile
            fd, path = tempfile.mkstemp(prefix="strix_sa_", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(key)
            os.chmod(path, 0o600)
            env["GOOGLE_APPLICATION_CREDENTIALS"] = path
            if ai_config.get("project_id"):
                env["GCLOUD_PROJECT"] = ai_config["project_id"]
            env.setdefault("GOOGLE_CLOUD_PROJECT", env.get("GCLOUD_PROJECT", ""))
        elif key:
            env["GOOGLE_API_KEY"] = key
            env["LLM_API_KEY"] = key
        env["LLM_API_KEY"] = key or env.get("LLM_API_KEY", "")
    else:
        if not key:
            raise ValueError("Strix taraması için API anahtarı gereklidir (%s sağlayıcısı)." % provider)
        env["LLM_API_KEY"] = key
        env["OPENAI_API_KEY"] = key  # litellm provider-env aynalama
        if provider in ("openai", "openai_compatible", "custom") and base_url:
            env["LLM_API_BASE"] = base_url
            env["OPENAI_BASE_URL"] = base_url

    # Kullanıcı hedefli sandbox ağı (localhost/İç ağ hedefleri için opsiyonel)
    if ai_config.get("sandbox_network"):
        env["STRIX_DOCKER_SANDBOX_NETWORK"] = str(ai_config["sandbox_network"]).strip()

    return env


class StrixScan:
    """Tek bir Strix tarama sürecini ve çıktılarını yönetir."""

    def __init__(self, scan_id, target, mode, workspace_dir, proc, cmd, log_path):
        self.scan_id = scan_id
        self.target = target
        self.mode = mode
        self.workspace_dir = workspace_dir   # strix_runs/ bu dizinin altında oluşur
        self.proc = proc
        self.cmd = cmd
        self.log_path = log_path
        self.started_at = time.time()
        self.finished = False
        self.exit_code = None

    # ---- Strix çıktı dosyaları ----
    def _runs_base(self):
        return os.path.join(self.workspace_dir, "strix_runs")

    def _latest_run_dir(self):
        base = self._runs_base()
        if not os.path.isdir(base):
            return None
        candidates = []
        for name in os.listdir(base):
            rj = os.path.join(base, name, "run.json")
            if os.path.isfile(rj):
                try:
                    candidates.append((os.path.getmtime(rj), os.path.join(base, name)))
                except OSError:
                    pass
        return max(candidates)[1] if candidates else None

    def _read_json(self, path, default):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    def _tail_log(self, limit=2500):
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - limit))
                return f.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def is_alive(self):
        if self.proc and self.proc.poll() is None:
            return True
        if not self.finished and self.proc is not None:
            self.finished = True
            self.exit_code = self.proc.returncode
        return False

    def live_findings(self):
        """vulnerabilities.json → uygulama bulgu şeması (canlı, tarama sırasında da güncel)."""
        run_dir = self._latest_run_dir()
        if not run_dir:
            return []
        vulns = self._read_json(os.path.join(run_dir, "vulnerabilities.json"), [])
        findings = []
        if not isinstance(vulns, list):
            return findings
        for v in vulns:
            if not isinstance(v, dict):
                continue
            sev_raw = str(v.get("severity") or "info").lower()
            evidence_parts = []
            for k in ("evidence", "poc_description", "technical_analysis"):
                if v.get(k):
                    evidence_parts.append(str(v[k])[:600])
            fix = v.get("remediation_steps") or "-"
            findings.append({
                "test": "Strix AI Pentest",
                "severity": SEVERITY_MAP.get(sev_raw, "ORTA" if sev_raw not in SEVERITY_MAP else "BİLGİ"),
                "severity_raw": sev_raw,
                "title": "[STRIX] %s" % (v.get("title") or "(başlıksız bulgu)"),
                "evidence": " || ".join(evidence_parts)[:1200] or "(kanıt kaydı yok)",
                "cwe": v.get("cwe") or "-",
                "cvss": v.get("cvss"),
                "endpoint": v.get("endpoint") or v.get("target") or "",
                "method": v.get("method") or "",
                "poc": v.get("poc_script_code") or "",
                "confidence": v.get("confidence") or "",
                "fix": fix,
                "description": (v.get("description") or "")[:800],
                "impact": (v.get("impact") or "")[:400],
            })
        return findings

    def status(self):
        alive = self.is_alive()
        run_dir = self._latest_run_dir()
        record = self._read_json(os.path.join(run_dir, "run.json"), {}) if run_dir else {}
        findings = self.live_findings()
        sev_summary = {}
        for f in findings:
            sev_summary[f["severity"]] = sev_summary.get(f["severity"], 0) + 1
        return {
            "success": True,
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "running": alive,
            "finished": (not alive) and self.finished,
            "exit_code": self.exit_code,
            "elapsed_sec": round(time.time() - self.started_at, 1),
            "run_status": record.get("status") or ("running" if alive else "unknown"),
            "run_name": os.path.basename(run_dir) if run_dir else None,
            "start_time": record.get("start_time"),
            "end_time": record.get("end_time"),
            "finding_count": len(findings),
            "severity_summary": sev_summary,
            "llm_cost_usd": record.get("total_llm_cost") or record.get("llm_cost_usd"),
            "log_tail": self._tail_log(),
        }

    def report(self):
        st = self.status()
        run_dir = self._latest_run_dir()
        return {
            "success": True,
            "scan": st,
            "findings": self.live_findings(),
            "run_dir": run_dir,
            "raw_record": self._read_json(os.path.join(run_dir, "run.json"), {}) if run_dir else {},
        }

    def cancel(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
        return {"success": True, "scan_id": self.scan_id}


class StrixManager:
    """Tek-örnek tarama yöneticisi (eşzamanlı tarama sınırı: 1)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._scans = {}  # scan_id -> StrixScan

    def start(self, target, ai_config, mode="standard", instruction="",
              max_turns=120, max_budget=None, fail_on=None, extra_targets=None):
        if mode not in SCAN_MODES:
            mode = "standard"
        binary = _which_strix()
        if not binary:
            return {"success": False,
                    "error": "STRIX_KURULU_DEĞİL",
                    "message": "Strix bulunamadı. Kurulum: pip install strix-agent — veya STRIX_BIN ortam değişkeni ile binary yolunu gösterin.",
                    "capabilities": strix_capabilities()}

        with self._lock:
            for s in self._scans.values():
                if s.is_alive():
                    return {"success": False,
                            "error": "STRIX_MEŞGUL",
                            "message": "Zaten çalışan bir Strix taraması var: %s (hedef: %s)" % (s.scan_id, s.target),
                            "active_scan_id": s.scan_id}

            scan_id = "strix_%s" % uuid.uuid4().hex[:10]
            workspace_dir = os.path.join(
                os.environ.get("STRIX_WORKSPACE", os.path.join(os.getcwd(), "strix_scans")),
                scan_id)
            os.makedirs(workspace_dir, exist_ok=True)
            log_path = os.path.join(workspace_dir, "strix_output.log")

            try:
                env = build_strix_env(ai_config or {})
            except ValueError as e:
                return {"success": False, "error": "STRIX_YAPILANDIRMA", "message": str(e)}

            cmd = [binary, "--target", target, "--non-interactive", "--scan-mode", mode,
                   "--max-turns", str(max_turns)]
            # Çoklu hedef (beyaz-kutu: kaynak + canlı URL birlikte taranabilir)
            for t in (extra_targets or [])[:5]:
                if isinstance(t, str) and t.strip():
                    cmd += ["--target", t.strip()]
            if max_budget:
                cmd += ["--max-budget", str(max_budget)]
            if fail_on in ("critical", "high", "medium", "low", "info"):
                cmd += ["--fail-on", fail_on]
            if instruction:
                cmd += ["--instruction", instruction]

            try:
                logf = open(log_path, "ab", buffering=0)
                proc = subprocess.Popen(
                    cmd, cwd=workspace_dir, env=env,
                    stdout=logf, stderr=subprocess.STDOUT,
                    start_new_session=True,  # kendi process group'u (iptal için)
                )
            except Exception as e:
                return {"success": False, "error": "STRIX_BAŞLATMA_HATASI", "message": str(e)[:300]}

            scan = StrixScan(scan_id, target, mode, workspace_dir, proc, cmd, log_path)
            self._scans[scan_id] = scan
            # Sınırsız büyümesin: eski bitmiş taramaları buda
            done = [k for k, v in self._scans.items() if v.finished and k != scan_id]
            for k in done[-20:]:
                del self._scans[k]

            return {"success": True, "scan_id": scan_id, "target": target, "mode": mode,
                    "command": " ".join(cmd[:6]) + " …", "message": "Strix taraması başlatıldı."}

    def get(self, scan_id):
        with self._lock:
            return self._scans.get(scan_id)

    def list_runs(self):
        out = []
        with self._lock:
            for s in self._scans.values():
                out.append({
                    "scan_id": s.scan_id, "target": s.target, "mode": s.mode,
                    "running": s.is_alive(), "started": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(s.started_at)),
                })
        return out


STRIX_MANAGER = StrixManager()
