#!/usr/bin/env python3
"""
Web Security Scanner — Strix Entegrasyon Motoru (%100 Tam Parite)
=================================================================
Strix (açık kaynak otonom AI pentest aracı, https://github.com/usestrix/strix)
CLI'sını gerçek bir subprocess olarak yönetir ve üretilen tüm artefaktları okur:

- Kurulum/uygunluk tespiti (binary, docker sandbox imajı, sürüm, özellikler)
- Tarama başlatma: tüm CLI bayrakları (--target, --target-list, --resume,
  --scan-mode, --scope-mode, --diff-base, --fail-on, --max-turns, --max-budget,
  --instruction-file, --workspace-file, --config, --mcp-config, --mcp-server,
  --mcp-exclude) ve tüm ortam değişkenleri (POSTMAN_API_KEY, PERPLEXITY_API_KEY,
  EXA_API_KEY, STRIX_REASONING_EFFORT, STRIX_DEDUPE_MODEL, STRIX_SANDBOX_* vb.)
- Canlı durum & Tam Artefakt Okuyucu:
  * run.json (durum, hedefler, LLM kullanım/maliyet istatistikleri)
  * vulnerabilities.json (tüm 25+ Strix bulgu alanı: CVSS breakdown, PoC,
    fix_pr_body, fix_verification, assumptions, counterevidence, code_locations,
    http_exchange_ids, dependency_metadata, agent_id/name)
  * .state/agents.json + .state/agents.db (alt-ajan ağacı, durumları, hataları ve olay sayısı)
  * coverage.json (agent_reported kapsam defteri + machine_observed + boşluklar/gaps)
  * penetration_test_report.md (Strix yerel yönetici raporu)
  * findings.sarif (OASIS SARIF 2.1.0 çıktısı)
  * vulnerabilities.csv (CSV dışa aktarma)
- İptal + CLI güncelleme (--update) + geçmiş tarama inceleme.
"""

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import threading
import time
import uuid

STRIX_MIN_VERSION = "1.0.0"

SEVERITY_MAP = {
    "critical": "KRİTİK",
    "high": "YÜKSEK",
    "medium": "ORTA",
    "low": "DÜŞÜK",
    "info": "BİLGİ",
}

SCAN_MODES = ("quick", "standard", "deep")

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
            "Otonom çoklu-ajan pentest (Scout/Exploit/Analyst topolojisi + canlı ajan ağacı)",
            "Docker izole sandbox içinde gerçek istismar doğrulaması (PoC)",
            "OWASP Top 10 + iş mantığı zafiyetleri (IDOR, auth, race condition)",
            "Tam şema: CVSS 3.1 breakdown, CWE/CVE, PoC, PR Fix Body, varsayımlar & karşı-kanıt",
            "Kapsam defteri (coverage.json), SARIF 2.1.0 (findings.sarif), CSV & Yönetici Markdown raporu",
            "Postman canlı koleksiyon (postman://) ve otonom web araması (Perplexity/Exa) entegrasyonu",
            "Hızlı/standart/derin tarama modları + kesilen taramaları devam ettirme (--resume)",
        ]
    elif caps["docker_available"]:
        caps["features"] = ["Sandbox imajı henüz çekilmemiş: docker pull ghcr.io/usestrix/strix-sandbox:1.3.0"]
    return caps


def build_strix_env(ai_config: dict, strix_env_opts: dict = None) -> dict:
    """UI'daki AI ve Strix ortam yapılandırmasını Strix'in ortam değişkenlerine çevirir."""
    env = dict(os.environ)
    env["STRIX_TELEMETRY"] = "0"

    provider = (ai_config.get("provider") or "openai").lower().strip()
    model = (ai_config.get("model") or "").strip()
    auth = ai_config.get("auth") if isinstance(ai_config.get("auth"), dict) else {}
    key = (ai_config.get("api_key") or auth.get("value") or "").strip()
    base_url = (ai_config.get("base_url") or "").strip()
    prefix = PROVIDER_MODEL_PREFIX.get(provider, "openai/")

    if not model:
        raise ValueError("Strix için model adı gereklidir (örn: gpt-4o, gemini-3.1-pro, openrouter modeli).")

    if model.startswith(prefix):
        env["STRIX_LLM"] = model
    else:
        env["STRIX_LLM"] = prefix + model

    if provider == "ollama":
        env["LLM_API_BASE"] = base_url or "http://localhost:11434"
        env["OLLAMA_API_BASE"] = env["LLM_API_BASE"]
        env["LLM_API_KEY"] = key or "ollama"
    elif provider == "vertex":
        auth_type = (auth.get("type") or "api_key").lower()
        if auth_type == "service_account" and key:
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
        env["OPENAI_API_KEY"] = key
        if provider in ("openai", "openai_compatible", "custom") and base_url:
            env["LLM_API_BASE"] = base_url
            env["OPENAI_BASE_URL"] = base_url

    # Strix gelişmiş ortam değişkenleri (%100 özellik paritesi)
    opts = strix_env_opts if isinstance(strix_env_opts, dict) else {}
    for opt_key, env_name in (
        ("postman_api_key", "POSTMAN_API_KEY"),
        ("perplexity_api_key", "PERPLEXITY_API_KEY"),
        ("exa_api_key", "EXA_API_KEY"),
        ("web_search_provider", "STRIX_WEB_SEARCH_PROVIDER"),
        ("reasoning_effort", "STRIX_REASONING_EFFORT"),
        ("dedupe_model", "STRIX_DEDUPE_MODEL"),
        ("dedupe_api_key", "DEDUPE_LLM_API_KEY"),
        ("sandbox_network", "STRIX_DOCKER_SANDBOX_NETWORK"),
        ("sandbox_cpus", "STRIX_SANDBOX_CPUS"),
        ("sandbox_mem_limit", "STRIX_SANDBOX_MEM_LIMIT"),
    ):
        val = (opts.get(opt_key) or ai_config.get(opt_key) or "").strip()
        if val:
            env[env_name] = val

    extra_headers = opts.get("llm_extra_headers") or ai_config.get("llm_extra_headers")
    if isinstance(extra_headers, dict) and extra_headers:
        env["LLM_EXTRA_HEADERS"] = json.dumps(extra_headers)
    elif isinstance(extra_headers, str) and extra_headers.strip().startswith("{"):
        env["LLM_EXTRA_HEADERS"] = extra_headers.strip()

    return env


def _read_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _read_text_file(path, limit=262144):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return ""


def map_strix_vulnerabilities(vulns):
    """vulnerabilities.json listesini 25+ alanın tamamıyla uygulama şemasına dönüştürür."""
    findings = []
    if not isinstance(vulns, list):
        return findings
    for v in vulns:
        if not isinstance(v, dict):
            continue
        sev_raw = str(v.get("severity") or "info").lower().strip()
        evidence_parts = []
        for k in ("evidence", "poc_description", "technical_analysis"):
            if v.get(k):
                evidence_parts.append(str(v[k])[:800])
        fix = v.get("remediation_steps") or "-"
        findings.append({
            "id": v.get("id") or "",
            "timestamp": v.get("timestamp") or "",
            "test": "Strix AI Pentest",
            "severity": SEVERITY_MAP.get(sev_raw, "ORTA" if sev_raw not in SEVERITY_MAP else "BİLGİ"),
            "severity_raw": sev_raw,
            "title": "[STRIX] %s" % (v.get("title") or "(başlıksız bulgu)"),
            "evidence": " || ".join(evidence_parts)[:1600] or "(kanıt kaydı yok)",
            "raw_evidence": v.get("evidence") or "",
            "technical_analysis": v.get("technical_analysis") or "",
            "poc_description": v.get("poc_description") or "",
            "poc": v.get("poc_script_code") or "",
            "cwe": v.get("cwe") or "-",
            "cve": v.get("cve") or "",
            "cvss": v.get("cvss"),
            "cvss_breakdown": v.get("cvss_breakdown") if isinstance(v.get("cvss_breakdown"), dict) else {},
            "endpoint": v.get("endpoint") or v.get("target") or "",
            "target": v.get("target") or "",
            "method": v.get("method") or "",
            "finding_class": v.get("finding_class") or "dynamic",
            "confidence": v.get("confidence") or "",
            "confidence_rationale": v.get("confidence_rationale") or "",
            "assumptions": v.get("assumptions") or "",
            "counterevidence": v.get("counterevidence") or "",
            "severity_change_conditions": v.get("severity_change_conditions") or "",
            "fix": fix,
            "fix_effort": v.get("fix_effort") or "",
            "fix_verification": v.get("fix_verification") or "",
            "fix_pr_body": v.get("fix_pr_body") or "",
            "code_locations": v.get("code_locations") if isinstance(v.get("code_locations"), list) else [],
            "http_exchange_ids": v.get("http_exchange_ids") if isinstance(v.get("http_exchange_ids"), list) else [],
            "dependency_metadata": v.get("dependency_metadata") if isinstance(v.get("dependency_metadata"), dict) else {},
            "agent_id": v.get("agent_id") or "",
            "agent_name": v.get("agent_name") or "",
            "description": (v.get("description") or "")[:1200],
            "impact": (v.get("impact") or "")[:800],
        })
    return findings


def extract_run_artifacts(run_dir):
    """Bir Strix run dizinindeki tüm artefaktları (ajan ağacı, kapsam, SARIF, MD, CSV, HTTP) okur."""
    if not run_dir or not os.path.isdir(run_dir):
        return {
            "agents": [],
            "coverage": {},
            "markdown_report": "",
            "sarif": None,
            "csv_report": "",
            "http_exchanges": [],
        }

    # 1) Alt-ajan topolojisi (.state/agents.json + .state/agents.db)
    state_dir = os.path.join(run_dir, ".state")
    agents_json = _read_json_file(os.path.join(state_dir, "agents.json"), {})
    statuses = agents_json.get("statuses") if isinstance(agents_json, dict) else {}
    names = agents_json.get("names") if isinstance(agents_json, dict) else {}
    parent_of = agents_json.get("parent_of") if isinstance(agents_json, dict) else {}
    errors = agents_json.get("errors") if isinstance(agents_json, dict) else {}
    skills_of = agents_json.get("skills") if isinstance(agents_json, dict) else {}
    tasks_of = agents_json.get("tasks") if isinstance(agents_json, dict) else {}

    # SQLite .state/agents.db içinden ajan başına mesaj/olay sayısını oku (varsa)
    msg_counts = {}
    db_path = os.path.join(state_dir, "agents.db")
    if os.path.isfile(db_path):
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=3)
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for tbl in tables:
                cols = [c[1] for c in cur.execute(f"PRAGMA table_info({tbl})").fetchall()]
                for col in ("agent_id", "session_id"):
                    if col in cols:
                        for aid, cnt in cur.execute(f"SELECT {col}, COUNT(*) FROM {tbl} GROUP BY {col}").fetchall():
                            if aid:
                                msg_counts[str(aid)] = msg_counts.get(str(aid), 0) + int(cnt)
                        break
            conn.close()
        except Exception:
            pass

    agents_list = []
    if isinstance(statuses, dict):
        for aid, st in statuses.items():
            agents_list.append({
                "id": aid,
                "name": (names or {}).get(aid) or aid,
                "status": st or "unknown",
                "parent_id": (parent_of or {}).get(aid),
                "error": (errors or {}).get(aid) or "",
                "skills": (skills_of or {}).get(aid) or [],
                "task": str((tasks_of or {}).get(aid) or "")[:300],
                "events_count": msg_counts.get(aid, 0),
            })

    # 2) Kapsam defteri (coverage.json)
    coverage = _read_json_file(os.path.join(run_dir, "coverage.json"), {})

    # 3) Yönetici Markdown raporu (penetration_test_report.md)
    md_report = _read_text_file(os.path.join(run_dir, "penetration_test_report.md"), limit=150000)

    # 4) SARIF 2.1.0 (findings.sarif)
    sarif_data = _read_json_file(os.path.join(run_dir, "findings.sarif"), None)

    # 5) CSV Raporu (vulnerabilities.csv)
    csv_report = _read_text_file(os.path.join(run_dir, "vulnerabilities.csv"), limit=100000)

    # 6) HTTP exchange kayıtları (varsa)
    http_exchanges = []
    for candidate in (
        os.path.join(run_dir, "http_exchanges.json"),
        os.path.join(state_dir, "http_exchanges.json"),
    ):
        if os.path.isfile(candidate):
            data = _read_json_file(candidate, [])
            if isinstance(data, list):
                http_exchanges = data[:100]
                break

    return {
        "agents": agents_list,
        "coverage": coverage if isinstance(coverage, dict) else {},
        "markdown_report": md_report,
        "sarif": sarif_data,
        "csv_report": csv_report,
        "http_exchanges": http_exchanges,
    }


class StrixScan:
    """Tek bir Strix tarama sürecini ve çıktılarını yönetir."""

    def __init__(self, scan_id, target, mode, workspace_dir, proc, cmd, log_path):
        self.scan_id = scan_id
        self.target = target
        self.mode = mode
        self.workspace_dir = workspace_dir
        self.proc = proc
        self.cmd = cmd
        self.log_path = log_path
        self.started_at = time.time()
        self.finished = False
        self.exit_code = None

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

    def _tail_log(self, limit=3500):
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
        run_dir = self._latest_run_dir()
        if not run_dir:
            return []
        vulns = _read_json_file(os.path.join(run_dir, "vulnerabilities.json"), [])
        return map_strix_vulnerabilities(vulns)

    def status(self):
        alive = self.is_alive()
        run_dir = self._latest_run_dir()
        record = _read_json_file(os.path.join(run_dir, "run.json"), {}) if run_dir else {}
        findings = self.live_findings()
        artifacts = extract_run_artifacts(run_dir) if run_dir else {}
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
            "agents_count": len(artifacts.get("agents") or []),
            "agents": artifacts.get("agents") or [],
            "llm_cost_usd": record.get("total_llm_cost") or record.get("llm_cost_usd"),
            "llm_usage": record.get("llm_usage") or record.get("total_llm_usage") or {},
            "log_tail": self._tail_log(),
        }

    def report(self):
        st = self.status()
        run_dir = self._latest_run_dir()
        artifacts = extract_run_artifacts(run_dir) if run_dir else {}
        return {
            "success": True,
            "scan": st,
            "findings": self.live_findings(),
            "run_dir": run_dir,
            "raw_record": _read_json_file(os.path.join(run_dir, "run.json"), {}) if run_dir else {},
            "artifacts": artifacts,
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
        self._scans = {}

    def _runs_base(self):
        return os.environ.get("STRIX_WORKSPACE", os.path.join(os.getcwd(), "strix_scans"))

    def _find_run_dir(self, run_name):
        base = self._runs_base()
        if not os.path.isdir(base) or not run_name:
            return None
        safe_name = os.path.basename(run_name.strip())
        for scan_id in os.listdir(base):
            cand = os.path.join(base, scan_id, "strix_runs", safe_name)
            if os.path.isdir(cand):
                return cand
        return None

    def get_run_info(self, run_name):
        run_dir = self._find_run_dir(run_name)
        if not run_dir:
            return None
        rec = _read_json_file(os.path.join(run_dir, "run.json"), {})
        ti = rec.get("targets_info") or []
        target = str(ti[0].get("original", "")) if ti and isinstance(ti[0], dict) else ""
        return {"run_name": run_name, "run_dir": run_dir, "target": target,
                "status": rec.get("status") or "unknown"}

    def get_report_by_run_name(self, run_name):
        """Geçmiş veya tamamlanmış bir taramanın tüm bulgu ve artefaktlarını döndürür."""
        run_dir = self._find_run_dir(run_name)
        if not run_dir:
            return None
        rec = _read_json_file(os.path.join(run_dir, "run.json"), {})
        vulns = _read_json_file(os.path.join(run_dir, "vulnerabilities.json"), [])
        findings = map_strix_vulnerabilities(vulns)
        artifacts = extract_run_artifacts(run_dir)
        sev_summary = {}
        for f in findings:
            sev_summary[f["severity"]] = sev_summary.get(f["severity"], 0) + 1
        ti = rec.get("targets_info") or []
        target = str(ti[0].get("original", "")) if ti and isinstance(ti[0], dict) else ""
        return {
            "success": True,
            "scan": {
                "scan_id": os.path.basename(os.path.dirname(os.path.dirname(run_dir))),
                "run_name": os.path.basename(run_dir),
                "target": target,
                "mode": rec.get("scan_mode") or "standard",
                "running": False,
                "finished": True,
                "run_status": rec.get("status") or "completed",
                "start_time": rec.get("start_time"),
                "end_time": rec.get("end_time"),
                "finding_count": len(findings),
                "severity_summary": sev_summary,
                "agents_count": len(artifacts.get("agents") or []),
                "agents": artifacts.get("agents") or [],
                "llm_cost_usd": rec.get("total_llm_cost") or rec.get("llm_cost_usd"),
            },
            "findings": findings,
            "run_dir": run_dir,
            "raw_record": rec,
            "artifacts": artifacts,
        }

    def list_all_runs(self):
        """Diskteki tüm Strix taramalarını özetler (resume + geçmiş artefakt inceleme)."""
        base = self._runs_base()
        runs = []
        if not os.path.isdir(base):
            return runs
        for scan_id in os.listdir(base):
            runs_dir = os.path.join(base, scan_id, "strix_runs")
            if not os.path.isdir(runs_dir):
                continue
            for name in os.listdir(runs_dir):
                run_dir = os.path.join(runs_dir, name)
                rj = os.path.join(run_dir, "run.json")
                if not os.path.isfile(rj):
                    continue
                rec = _read_json_file(rj, {})
                vulns = _read_json_file(os.path.join(run_dir, "vulnerabilities.json"), [])
                n = len(vulns) if isinstance(vulns, list) else 0
                ti = rec.get("targets_info") or []
                target = str(ti[0].get("original", "")) if ti and isinstance(ti[0], dict) else ""
                runs.append({
                    "run_name": name,
                    "scan_id": scan_id,
                    "target": target,
                    "mode": rec.get("scan_mode") or "standard",
                    "status": rec.get("status") or "unknown",
                    "start_time": rec.get("start_time"),
                    "end_time": rec.get("end_time"),
                    "findings": n,
                    "resumable": os.path.isfile(os.path.join(run_dir, ".state", "agents.json")),
                    "has_sarif": os.path.isfile(os.path.join(run_dir, "findings.sarif")),
                    "has_coverage": os.path.isfile(os.path.join(run_dir, "coverage.json")),
                    "has_markdown": os.path.isfile(os.path.join(run_dir, "penetration_test_report.md")),
                })
        runs.sort(key=lambda r: str(r.get("start_time") or ""), reverse=True)
        return runs[:100]

    def update_strix(self):
        binary = _which_strix()
        if not binary:
            return {"success": False, "error": "STRIX_KURULU_DEĞİL", "message": "Strix bulunamadı."}
        try:
            out = subprocess.run([binary, "--update"], capture_output=True, text=True, timeout=300)
            return {"success": out.returncode == 0,
                    "output": ((out.stdout or "") + (out.stderr or ""))[-2000:]}
        except Exception as e:
            return {"success": False, "error": str(e)[:200]}

    def start(self, target, ai_config, mode="standard", instruction="",
              max_turns=120, max_budget=None, fail_on=None, extra_targets=None,
              scope_mode=None, diff_base=None, config=None, mcp_config=None,
              mcp_servers=None, mcp_exclude=None, target_list=None,
              workspace_files=None, resume=None, strix_env_opts=None):
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

            run_name = (resume or "").strip()
            if run_name:
                info = self.get_run_info(run_name)
                if not info:
                    return {"success": False, "error": "STRIX_RUN_BULUNAMADI",
                            "message": "Önceki tarama bulunamadı: %s" % run_name}
                workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(info["run_dir"])))
                target = target or info.get("target") or "(resume)"
                scan_id = os.path.basename(workspace_dir) or ("strix_%s" % uuid.uuid4().hex[:10])
            else:
                if not target:
                    return {"success": False, "error": "EKSİK_HEDEF",
                            "message": "Yeni tarama için url, resume için run adı gereklidir."}
                scan_id = "strix_%s" % uuid.uuid4().hex[:10]
                workspace_dir = os.path.join(self._runs_base(), scan_id)
                os.makedirs(workspace_dir, exist_ok=True)

            log_path = os.path.join(workspace_dir, "strix_output.log")

            try:
                env = build_strix_env(ai_config or {}, strix_env_opts or {})
            except ValueError as e:
                return {"success": False, "error": "STRIX_YAPILANDIRMA", "message": str(e)}

            def _write(rel, content, limit=262144):
                path = os.path.join(workspace_dir, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(str(content)[:limit])
                return path

            cmd = [binary, "--non-interactive", "--scan-mode", mode,
                   "--max-turns", str(max_turns)]

            if run_name:
                cmd += ["--resume", run_name]
            else:
                cmd += ["--target", target]
                for t in (extra_targets or [])[:5]:
                    if isinstance(t, str) and t.strip():
                        cmd += ["--target", t.strip()]
                tl = [str(t).strip() for t in (target_list or []) if str(t).strip()][:50]
                if tl:
                    cmd += ["--target-list", _write("targets.txt", "\n".join(tl))]

            if max_budget:
                cmd += ["--max-budget", str(max_budget)]
            if fail_on in ("critical", "high", "medium", "low", "info"):
                cmd += ["--fail-on", fail_on]
            if instruction:
                cmd += ["--instruction-file", _write("instruction.txt", instruction, 8000)]
            if scope_mode in ("auto", "diff", "full"):
                cmd += ["--scope-mode", scope_mode]
                if scope_mode == "diff" and diff_base:
                    cmd += ["--diff-base", str(diff_base)[:200]]
            if isinstance(config, dict) and config:
                cmd += ["--config", _write("cli-config.json", json.dumps(config))]
            if isinstance(mcp_config, dict) and mcp_config:
                cmd += ["--mcp-config", _write("mcp-servers.json", json.dumps(mcp_config))]
            for name in (mcp_servers or [])[:10]:
                if isinstance(name, str) and name.strip():
                    cmd += ["--mcp-server", name.strip()]
            for name in (mcp_exclude or [])[:10]:
                if isinstance(name, str) and name.strip():
                    cmd += ["--mcp-exclude", name.strip()]
            for wf in (workspace_files or [])[:5]:
                if not isinstance(wf, dict):
                    continue
                name = os.path.basename(str(wf.get("name") or "")).strip()
                if not name or name.startswith("."):
                    continue
                path = _write("workspace_files/%s" % name, wf.get("content") or "")
                dest = str(wf.get("dest") or "").strip()
                cmd += ["--workspace-file", path + (":" + dest if dest else "")]

            try:
                logf = open(log_path, "ab", buffering=0)
                proc = subprocess.Popen(
                    cmd, cwd=workspace_dir, env=env,
                    stdout=logf, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except Exception as e:
                return {"success": False, "error": "STRIX_BAŞLATMA_HATASI", "message": str(e)[:300]}

            scan = StrixScan(scan_id, target, mode, workspace_dir, proc, cmd, log_path)
            self._scans[scan_id] = scan
            done = [k for k, v in self._scans.items() if v.finished and k != scan_id]
            for k in done[-20:]:
                del self._scans[k]

            return {"success": True, "scan_id": scan_id, "target": target, "mode": mode,
                    "resumed_run": run_name or None,
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
