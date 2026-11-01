import json
import re
import time
from urllib.parse import urlsplit
from typing import List, Dict, Any, Optional
from ai_connector import AIProviderFactory
from json_utils import extract_json as _extract_json_impl

# =============================================================
# Faz 6G-v2: AI Ajan Orkestratörü (Strix metodolojisiyle hizalı)
# =============================================================
# Üçlü ajan ekibi (Scout → Strategist → Analyst) gerçek keşif verisiyle
# (crawler site haritası, formlar, başlıklar, temel aktif tarama bulguları)
# çalışır. Her hipotez rate-limited aktif testle DOĞRULANIR; Analyst yalnız
# HTTP kanıtına bakarak karar verir (Spekülatif bulgu üretilmez — Strix'in
# "exploit-verified findings" ilkesi).
#
# v1'den farkları (yüzeysellik düzeltmesi):
# - Gerçek saldırı yüzeyi context'i (boş JSON ile başlamıyor)
# - Devre kesici artık yalnız connector hata sözdiziminde tetiklenir
#   ("Error:" öneki), içerikte geçen rastgele "error" kelimesinde değil
# - Yapılandırılmış JSON verdict (analyst): TP/FP + güven + şiddet
# - Kanıt özetleri token bütçesiyle kırpılır, tekrar testler elenir
# - Final Analyst raporu: yönetici özeti + zincirler + önceliklendirilmiş düzeltme
# =============================================================

MAX_CONTEXT_CHARS = 9000      # tek LLM çağrısına gidecek azami context
MAX_BODY_CHARS = 3000         # analyst'e gidecek azami gövde kesiti

ERROR_PREFIXES = ("Error:", "error:")


def _is_llm_error(text: str) -> bool:
    t = (text or "").strip()
    return (not t) or t.startswith(ERROR_PREFIXES) or len(t) < 3


def _trim(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…[kırptım]"


def _extract_json(text, want="list"):
    """json_utils.extract_json geriye donuk uyumlu sarmalayici (deterministik onarim dahil)."""
    return _extract_json_impl(text, "list" if want == "list" else "object")


# =============================================================
# Faz 1: Öncelikli bağlam özeti + kapsam matrisi + tur geçmişi (deterministik, LLM'siz)
# =============================================================
_SECURITY_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "set-cookie", "access-control-allow-origin", "server", "x-powered-by",
)


def _prioritized_surface(scan_state, limit=3600):
    """Saldırı yüzeyini ÖNCELİK sırasına göre kompakt özetler ve token bütçesine sığdırır.

    Kaba karakter kesmesi yerine (eski _trim(context, 3200)); teknoloji parmak izleri,
    güvenlik başlıkları, parametreli uç noktalar/formlar ve temel bulgular korunur. Böylece
    büyük hedeflerde Stratejist'e giden bağlamdan kritik veri düşmez.
    """
    if not isinstance(scan_state, dict):
        return _trim(str(scan_state), limit)
    surface = scan_state.get("attack_surface") or {}
    pages = [p for p in (surface.get("pages") or []) if isinstance(p, str)]
    forms = surface.get("forms") or []
    headers = scan_state.get("response_headers") or {}
    param_pages = [p for p in pages if "?" in p]
    plain_pages = [p for p in pages if "?" not in p]
    sec_headers = {k: v for k, v in headers.items() if str(k).lower() in _SECURITY_HEADERS}
    blocks = [
        ("target", scan_state.get("target")),
        ("technologies", scan_state.get("technology_fingerprints") or []),
        ("security_headers", sec_headers),
        ("forms", forms),
        ("parameterized_endpoints", param_pages),
        ("static_findings", scan_state.get("static_findings") or []),
        ("other_pages", plain_pages),
    ]
    out = {}
    budget = max(400, int(limit))
    for key, val in blocks:
        chunk = json.dumps({key: val}, ensure_ascii=False, default=str)
        if len(chunk) > budget and isinstance(val, list):
            trimmed = []
            for item in val:
                if len(json.dumps(trimmed + [item], ensure_ascii=False, default=str)) > budget:
                    break
                trimmed.append(item)
            val = trimmed
            chunk = json.dumps({key: val}, ensure_ascii=False, default=str)
        out[key] = val
        budget -= len(chunk)
        if budget <= 0:
            break
    return json.dumps(out, ensure_ascii=False, default=str)


def build_coverage_matrix(scan_state, executed):
    """Uç nokta × parametre × zafiyet sınıfı kapsam matrisi (hangi kombinasyon test edildi / bulundu)."""
    tested = {}
    for e in (executed or []):
        if not isinstance(e, dict):
            continue
        key = (str(e.get("url", ""))[:120], str(e.get("param", "")))
        rec = tested.setdefault(key, {"probes": 0, "verdicts": {}})
        rec["probes"] += 1
        v = str(e.get("verdict", "?"))
        rec["verdicts"][v] = rec["verdicts"].get(v, 0) + 1
    rows = []
    for (url, param), rec in tested.items():
        verdicts = rec["verdicts"]
        if any(v == "VULNERABLE" for v in verdicts):
            status = "vulnerable"
        elif verdicts and all(v.startswith("BLOCKED") for v in verdicts):
            status = "blocked"
        elif any(v == "INCONCLUSIVE" for v in verdicts):
            status = "inconclusive"
        else:
            status = "covered"
        rows.append({"endpoint": url, "param": param, "probes": rec["probes"],
                     "status": status, "verdicts": verdicts})
    surface = (scan_state or {}).get("attack_surface") or {}
    seen = {(r["endpoint"], r["param"]) for r in rows}
    untested = []
    try:
        from urllib.parse import urlsplit, parse_qs
        for p in (surface.get("pages") or []):
            if isinstance(p, str) and "?" in p:
                for pname in parse_qs(urlsplit(p).query):
                    cand = {"endpoint": p[:120], "param": pname}
                    if (p[:120], pname) not in seen and cand not in untested:
                        untested.append(cand)
    except Exception:
        pass
    return {"tested": rows, "untested_sample": untested[:20],
            "tested_count": len(rows), "untested_count": len(untested)}


def _history_from_executed(executed, loops):
    """Tur bazında dürüst geçmiş (eski sürüm her tura aynı sayıyı yazıyordu)."""
    hist = []
    for ln in range(1, int(loops) + 1):
        entries = [e for e in (executed or []) if isinstance(e, dict) and e.get("loop") == ln]
        verified = sum(1 for e in entries if e.get("verdict") == "VULNERABLE")
        blocked = sum(1 for e in entries if str(e.get("verdict", "")).startswith("BLOCKED"))
        hist.append({"step": ln, "result": "%d prob · %d doğrulanmış · %d engellenmiş" % (
            len(entries), verified, blocked)})
    return hist


# =============================================================
# Faz 2: Operatör onayı (PentAGI "ask" bariyeri) + ajan başına model doğrulama
# =============================================================
CONFIRM_YES = "Evet, test et"
CONFIRM_NO = "Hayır, atla"

_SENSITIVE_ACTION_RE = re.compile(
    r"(?:^|[/_.\-=&?])(delete|remove|destroy|drop|purge|wipe|erase|logout|log-out|signout|sign-out|"
    r"unsubscribe|deactivate|disable|terminate|cancel|refund|transfer|withdraw|payment|pay|checkout|"
    r"purchase|reset|shutdown|restart|reboot|revoke|ban|unlink)(?=$|[/_.\-=&?])", re.I)

_ROLE_NAMES = ("scout", "strategist", "analyst", "reporter", "mentor")
_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9._:/@+-]{1,120}$")


def _needs_confirmation(url, param, payload, task=None):
    """Prob durum değiştirebilecek bir uca dokunuyorsa ya da LLM emin değilse gerekçe döndürür; aksi hâlde "".

    Yalnızca GET + salt-okunur payload kullanılsa da /delete, /logout, /payment gibi uçlar
    kötü tasarlanmış uygulamalarda durumu değiştirebilir; bu yüzden operatöre sorulur.
    """
    try:
        parts = urlsplit(str(url or ""))
        surface = "%s?%s&%s=%s" % (parts.path, parts.query, param or "", payload or "")
    except ValueError:
        surface = str(url or "")
    m = _SENSITIVE_ACTION_RE.search(surface)
    if m:
        return "durum değiştirebilecek bir uç/eylem ('%s')" % m.group(1).lower()
    flag = task.get("needs_confirmation") if isinstance(task, dict) else None
    if flag is True or str(flag).strip().lower() in ("true", "yes", "1"):
        return "model bu probun güvenli olduğundan emin değil"
    return ""


def _clean_role_models(raw):
    """Ajan başına model adlarını doğrular; geçersiz adlar yok sayılır (URL'ye giden değerler)."""
    out = {}
    if isinstance(raw, dict):
        for role in _ROLE_NAMES:
            value = str(raw.get(role) or "").strip()
            if value and _MODEL_NAME_RE.match(value):
                out[role] = value
    return out


class AIAgent:
    """Genel ajan yapısı."""
    def __init__(self, name: str, role_prompt: str, connector):
        self.name = name
        self.role_prompt = role_prompt
        self.connector = connector

    def think(self, context: str, user_input: str = "") -> str:
        full_prompt = f"{self.role_prompt}\n\nCONTEXT:\n{_trim(context, MAX_CONTEXT_CHARS)}\n\nINPUT: {user_input}"
        try:
            self.connector._agent_label = self.name
        except Exception:
            pass
        return self.connector.chat(full_prompt)

    def think_json(self, context: str, user_input: str = "", want: str = "object") -> dict:
        """JSON bekleyen ajan çağrıları: chat_json (JSON modu + deterministik onarım + düzeltici retry)."""
        full_prompt = f"{self.role_prompt}\n\nCONTEXT:\n{_trim(context, MAX_CONTEXT_CHARS)}\n\nINPUT: {user_input}"
        try:
            self.connector._agent_label = self.name
        except Exception:
            pass
        if hasattr(self.connector, "chat_json"):
            return self.connector.chat_json(full_prompt, want=want)
        raw = self.connector.chat(full_prompt)
        data = _extract_json(raw, want)
        return {"data": data, "raw": raw, "ok": data is not None, "repaired": False, "fixed": False}


# =============================================================
# Claude-Red Dinamik Saldırı Playbook'ları (Context-Aware Skill Priming)
# Keşif aşamasında tespit edilen teknoloji, başlık, form veya yollara göre
# Scout ve Strategist ajanlarına yalnızca ilgili uzman metodolojileri yükler.
# =============================================================
CLAUDE_RED_PLAYBOOKS = {
    "jwt_auth": (
        "[SKILL: offensive-jwt & offensive-oauth] "
        "Check JWT tokens for alg:none, RS256->HS256 key confusion, 'kid' path traversal/SQLi, "
        "'jku'/'x5u' SSRF key spoofing, and missing exp. On OAuth/OIDC endpoints (/authorize, /callback, /oauth), "
        "test missing 'state' (CSRF), redirect_uri open-redirect chaining, and response_type=token leakage."
    ),
    "graphql": (
        "[SKILL: offensive-graphql] "
        "Target /graphql or /api/graphql with Introspection (__schema), field suggestion oracle probes, "
        "alias-based IDOR/rate-limit bypass, and nested query depth checks."
    ),
    "waf_bypass": (
        "[SKILL: offensive-waf-bypass & offensive-parameter-pollution] "
        "WAF/CDN detected on target. Avoid noisy raw script tags; prefer HTTP Parameter Pollution (duplicate params), "
        "URL/Unicode encoding variations, JSON/form Content-Type switching, and differential boolean/math probes."
    ),
    "api_bola_mass": (
        "[SKILL: offensive-api-security & offensive-api-abuse] "
        "Test REST/JSON endpoints for BOLA/IDOR (numeric/UUID object IDs), BFLA (admin/role parameters), "
        "Mass Assignment (role=admin, is_admin=true), and pagination/limit boundary abuse."
    ),
    "ssrf_cloud": (
        "[SKILL: offensive-ssrf & offensive-cloud] "
        "URL-like parameters (url, redirect, next, webhook, callback, uri) should be tested for loopback/internal "
        "differentials (127.0.0.1, localhost) and cloud metadata pivot indicators."
    ),
    "ssti_rce": (
        "[SKILL: offensive-ssti & offensive-sqli] "
        "Use non-destructive polyglot math evaluation markers ({{7*7}}, 49, <%= 7*7 %>) for SSTI, "
        "and single-quote / boolean differential (' AND 1=1 vs ' AND 1=2) for SQLi/NoSQLi."
    ),
}


def select_claude_red_playbooks(initial_data: Dict[str, Any], target_url: str) -> List[str]:
    """Hedefin gerçek keşif verisine (başlıklar, teknolojiler, URL'ler, bulgular) göre ilgili Claude-Red playbook'larını seçer."""
    selected = []
    blob = (json.dumps(initial_data, ensure_ascii=False, default=str) + " " + (target_url or "")).lower()

    if any(k in blob for k in ("jwt", "eyj", "bearer", "oauth", "client_id", "redirect_uri", "openid")):
        selected.append("jwt_auth")
    if any(k in blob for k in ("graphql", "gql", "__schema", "__typename")):
        selected.append("graphql")
    if any(k in blob for k in ("cloudflare", "cf-ray", "akamai", "incapsula", "modsecurity", "aws waf", "waf")):
        selected.append("waf_bypass")
    if any(k in blob for k in ("/api/", "/v1/", "/v2/", "json", "id=", "uid=", "user", "account", "role")):
        selected.append("api_bola_mass")
    if any(k in blob for k in ("url=", "redirect=", "next=", "callback=", "uri=", "webhook", "amazonaws", "googleusercontent")):
        selected.append("ssrf_cloud")

    selected.append("ssti_rce")
    return selected


class AIOrchestrator:
    """
    Ajanlar arası döngüyü yöneten ve maliyet kontrolü yapan ana orkestratör.
    """
    def __init__(self, provider_config: dict, max_loops: int = 3, max_tests_per_loop: int = 4):
        self.provider_config = dict(provider_config or {})
        self.connector = AIProviderFactory.create_connector(self.provider_config)
        self.max_loops = max_loops
        self.max_tests_per_loop = max_tests_per_loop
        # Küçük/yerel model modu: verimsiz turdan sonra bağımsız Mentor önerisi (varsayılan kapalı)
        self.small_model_mode = bool(self.provider_config.get("small_model_mode"))
        # Ajan başına model (aynı sağlayıcı ve kimlik bilgisiyle; PentAGI pconfig uyarlaması)
        self.role_models = _clean_role_models(self.provider_config.get("role_models"))
        self._role_connectors = {}

        self.scout = AIAgent(
            "The Scout",
            "You are The Scout, an elite web-application recon specialist in an autonomous red team. "
            "You are given REAL scan data: HTTP headers, technology fingerprints, crawled site map, "
            "discovered forms/parameters, and baseline active-scan findings. "
            "Produce a precise attack-surface assessment: (1) most attack-worthy parameters/endpoints "
            "with WHY (technology-specific risks), (2) likely vulnerability classes per entry point, "
            "(3) what baseline findings imply for chaining. Be specific: name exact URLs, parameters, "
            "technologies from the data. Never invent URLs that are not in the data. Max ~200 words.",
            self._connector_for("scout")
        )
        self.strategist = AIAgent(
            "The Strategist",
            "You are The Strategist, a red-team planner. Given the Scout's assessment, the real attack "
            "surface, and a history of already-executed tests, choose the NEXT set of concrete probes "
            "(max 4) that are NOT already in the history. Reply with ONLY a JSON array, no prose:\n"
            '[{"url": "<exact url from the data>", "param": "<exact param name>", "payload": "<harmless read-only probe payload>", '
            '"vuln_class": "sqli|xss|ssti|ssrf|open_redirect|idor|nosqli|jwt_oauth|graphql|hpp|cors|other", "reason": "<one line>", "needs_confirmation": false}]\n'
            "Rules: payloads must be harmless and read-only (e.g. error-based markers, reflection markers "
            "like wzxqmk731, {{7*7}}, benign internal URLs for SSRF differentials, numeric ID swaps). "
            "No INSERT/UPDATE/DELETE, no destructive commands, no external canary domains you invented. "
            "Set needs_confirmation to true when a probe could change server state, touches account/admin/payment/logout/delete-style actions, or you are unsure it is safe (the operator will be asked first). "
            "If the surface is exhausted or nothing meaningful remains, reply with [].",
            self._connector_for("strategist")
        )
        self.analyst = AIAgent(
            "The Analyst",
            "You are The Analyst, a strict vulnerability triage expert. You receive ONE executed probe: "
            "the request (url/param/payload), and the REAL HTTP response (status, trimmed body). "
            "Judge ONLY from the evidence shown — do not assume. Decide true vs false positive. "
            "Reply with ONLY JSON: {\"verdict\": \"VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE\", "
            "\"confidence\": \"high|medium|low\", \"severity\": \"critical|high|medium|low\", "
            "\"cwe\": \"CWE-XX or -\", \"evidence_quote\": \"<short excerpt from the response proving it>\", "
            "\"reasoning\": \"<2-3 sentences>\"}. "
            "Be strict: reflection of a harmless marker inside an HTML-escaped context is NOT vulnerable; "
            "a length difference alone is NOT SQLi; a generic 500 page is NOT proof. "
            "But these ARE concrete positive signals: (a) your payload's raw HTML appearing verbatim "
            "unescaped in an HTML context (e.g. <img ... onerror=...>) = reflected XSS (high); "
            "(b) a database engine error message (SQL syntax error etc.) triggered by your payload = SQLi; "
            "(c) a template expression evaluated to its computed value ({{7*7}} -> 49) = SSTI. "
            "VULNERABLE requires one of these concrete signals in the shown response.",
            self._connector_for("analyst")
        )
        self.reporter = AIAgent(
            "The Reporter",
            "You are The Reporter, a senior security consultant writing the final red-team section. "
            "You receive two evidence sets: 'verified_findings' (AI-proven via live probe + HTTP evidence) "
            "and 'deterministic_engine_findings' (rule-based baseline scan results). Write a concise "
            "Markdown report with EXACTLY these sections: '### Yönetici Özeti' (3-4 sentences, business "
            "impact across BOTH evidence sets), '### Doğrulanan AI Bulguları' (list verified_findings; say "
            "if none), '### Saldırı Zincirleri' (how findings chain; say so if none), "
            "'### Önceliklendirilmiş Düzeltme' (numbered list, most urgent first, concrete; include "
            "critical/high deterministic findings too and mark them '(deterministik motor)'). "
            "Base every claim ONLY on the provided data; do not invent new findings. Write in Turkish.",
            self._connector_for("reporter")
        )

        self.mentor = AIAgent(
            "The Mentor",
            "You are The Mentor, an independent senior pentest reviewer (PentAGI-style adviser). You receive "
            "the results of the previous probing round and the coverage matrix; the round found nothing. "
            "In at most 4 short bullet points, advise the Strategist what to change next: untested entry "
            "points or parameters, a different vulnerability class, or a different (still harmless, "
            "read-only) payload style. Never suggest destructive, state-changing or out-of-scope actions. "
            "Plain text only.",
            self._connector_for("mentor")
        )

    def _connector_for(self, role):
        """Ajanın bağlayıcısı: role_models'ta farklı bir model varsa ayrı bağlayıcı (önbellekli)."""
        model = self.role_models.get(role)
        default_model = str(self.provider_config.get("model") or "").strip()
        if not model or model == default_model:
            return self.connector
        if model not in self._role_connectors:
            cfg = dict(self.provider_config)
            cfg["model"] = model
            for key in ("deployment", "model_id"):
                if cfg.get(key):
                    cfg[key] = model
            self._role_connectors[model] = AIProviderFactory.create_connector(cfg)
        return self._role_connectors[model]

    def _all_connectors(self):
        seen, out = set(), []
        for conn in [self.connector] + list(self._role_connectors.values()):
            if id(conn) not in seen:
                seen.add(id(conn))
                out.append(conn)
        return out

    def _telemetry_summary(self):
        """Ajan bazında LLM telemetrisi (çağrı, gecikme, token) — bağlayıcı kayıtlarından toplanır."""
        calls = []
        for conn in self._all_connectors():
            try:
                calls.extend(conn.get_telemetry() or [])
            except Exception:
                pass
        by_agent = {}
        total_in = 0
        total_out = 0
        for c in calls:
            if not isinstance(c, dict):
                continue
            a = c.get("agent") or "?"
            d = by_agent.setdefault(a, {"calls": 0, "latency_ms": 0, "ok": 0,
                                        "input_tokens": 0, "output_tokens": 0})
            d["calls"] += 1
            if c.get("model"):
                d["model"] = c.get("model")
            d["latency_ms"] += c.get("latency_ms", 0) or 0
            d["ok"] += 1 if c.get("ok") else 0
            u = c.get("usage") or {}
            d["input_tokens"] += u.get("input_tokens") or 0
            d["output_tokens"] += u.get("output_tokens") or 0
            total_in += u.get("input_tokens") or 0
            total_out += u.get("output_tokens") or 0
        return {
            "total_calls": len(calls),
            "total_latency_ms": sum((c.get("latency_ms", 0) or 0) for c in calls if isinstance(c, dict)),
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "by_agent": by_agent,
        }

    def _compress_history(self, history: List[Dict]) -> str:
        """Maliyet kontrolü: geçmiş testleri kompakt imza listesine indirger."""
        if not history:
            return "No tests executed yet."
        lines = []
        for entry in history[-25:]:
            lines.append("- %s param=%s payload=%.40s → %s" % (
                entry.get("url", "?")[:90], entry.get("param", "?"),
                str(entry.get("payload", "")), entry.get("verdict", "?")))
        return "\n".join(lines)

    def orchestrate_scan(self, target_url: str, initial_data: Dict[str, Any], active_scanner_callback, progress_callback=None, control=None):
        """
        Yapay Zeka Destekli Dinamik Tarama Döngüsü.
        active_scanner_callback: (url, param, payload) -> yanıt sözlüğü.
        progress_callback(agent, message): canlı düşünce akışı için opsiyonel.
        """
        loop_count = 0
        executed: List[Dict] = []          # çalıştırılan tüm test imzaları
        tested_signatures = set()
        verified_findings: List[Dict] = []
        scout_report = ""
        errors: List[str] = []

        def emit(agent, msg):
            if progress_callback:
                try:
                    progress_callback(agent, msg)
                except Exception:
                    pass

        def cancelled():
            try:
                return bool(control is not None and control.is_cancelled())
            except Exception:
                return False

        was_cancelled = False
        steering_notes: List[str] = []
        mentor_advice = ""
        mentor_calls = 0

        active_playbooks = select_claude_red_playbooks(initial_data, target_url)
        playbook_text = "\n".join(CLAUDE_RED_PLAYBOOKS[k] for k in active_playbooks if k in CLAUDE_RED_PLAYBOOKS)
        initial_data["loaded_claude_red_skills"] = active_playbooks

        context = json.dumps(initial_data, ensure_ascii=False, default=str)
        emit("system", "Bağlam hazır: %d sayfa, %d form, %d temel bulgu | Claude-Red Playbook'ları yüklendi: %s" % (
            len((initial_data.get("attack_surface") or {}).get("pages", [])),
            len((initial_data.get("attack_surface") or {}).get("forms", [])),
            len(initial_data.get("static_findings", [])),
            ", ".join(active_playbooks)))

        while loop_count < self.max_loops:
            if cancelled():
                was_cancelled = True
                emit("system", "⏹️ Tarama iptal edildi; yeni tur başlatılmadı.")
                break
            loop_count += 1

            # 1. KEŞİF (The Scout) — her turda biriken bulgularla yeniden değerlendirir
            emit("scout", "Tur %d/%d: Saldırı yüzeyi analiz ediliyor…" % (loop_count, self.max_loops))
            scout_input = ("Target: %s\nActive Claude-Red Specialist Playbooks:\n%s\nScan data:\n%s\nPrevious loop verdict: %s\nFindings so far: %s"
                           % (target_url, playbook_text, _trim(context, 6000), _trim(scout_report, 1200),
                              _trim(json.dumps([f.get("summary") for f in verified_findings], default=str), 1500)))
            scout_report = self.scout.think(scout_input)
            if _is_llm_error(scout_report):
                errors.append("Scout LLM hatası: %s" % _trim(scout_report, 120))
                break
            emit("scout", _trim(scout_report, 400))

            # 2. STRATEJİ (The Strategist)
            emit("strategist", "Tur %d: Hipotez planlanıyor…" % loop_count)
            strategy_ctx = ("Target: %s\nActive Claude-Red Playbooks:\n%s\nScout assessment: %s\nFull attack surface: %s\nAlready executed tests (DO NOT repeat):\n%s"
                            % (target_url, playbook_text, _trim(scout_report, 2000), _prioritized_surface(initial_data, 3600),
                               self._compress_history(executed)))
            new_notes = []
            if control is not None and hasattr(control, "pop_notes"):
                try:
                    new_notes = [str(n)[:500] for n in (control.pop_notes() or []) if str(n).strip()]
                except Exception:
                    new_notes = []
            if new_notes:
                steering_notes.extend(new_notes)
                emit("strategist", "📝 Kullanıcı notu planlamaya eklendi: %s" % _trim("; ".join(new_notes), 200))
            if steering_notes:
                strategy_ctx += ("\nUSER STEERING NOTES (operator instructions; follow them unless they conflict "
                                 "with the safety/scope rules):\n- " + "\n- ".join(steering_notes[-5:]))
            if mentor_advice:
                strategy_ctx += "\nMENTOR ADVICE (independent reviewer of the previous round):\n" + mentor_advice
            if cancelled():
                was_cancelled = True
                emit("system", "⏹️ Tarama iptal edildi; planlama yapılmadı.")
                break
            plan_res = self.strategist.think_json(strategy_ctx, want="list")
            if not plan_res.get("ok") and _is_llm_error(plan_res.get("raw", "")):
                errors.append("Strategist LLM hatası: %s" % _trim(plan_res.get("raw", ""), 120))
                break
            if plan_res.get("fixed"):
                emit("strategist", "Strateji çıktısı bozuktu; düzeltici tek tekrar ile onarıldı.")
            plan = plan_res.get("data")
            if not isinstance(plan, list):
                emit("strategist", "Strateji çıktısı JSON olarak ayrıştırılamadı; döngü burada sonlanıyor.")
                errors.append("Strateji JSON ayrıştırılamadı (tur %d)" % loop_count)
                break

            plan = [t for t in plan if isinstance(t, dict) and t.get("url")][: self.max_tests_per_loop]
            if not plan:
                emit("strategist", "Stratejist yeni test önermedi — keşif yüzeyi tükendi.")
                break

            # 3. AKTİF DOĞRULAMA (sistem yürütür; kanıt toplanır)
            for task in plan:
                param = str(task.get("param") or "").strip()
                payload = str(task.get("payload") or "").strip()
                url = str(task.get("url") or target_url).strip()
                sig = (url, param, payload)
                if sig in tested_signatures or not param:
                    continue
                tested_signatures.add(sig)
                if cancelled():
                    was_cancelled = True
                    break

                # Riskli (durum değiştirebilecek) uçlar ya da LLM'in emin olmadığı problar için operatöre sor.
                # Kontrol yoksa (senkron mod) veya cevap gelmezse güvenli varsayılan: testi atla.
                confirm_reason = _needs_confirmation(url, param, payload, task)
                if confirm_reason:
                    question = ("AI şu testi yapmak istiyor: GET %s [%s] ← %s. Gerekçe: %s. Test edilsin mi?"
                                % (url[:120], param, _trim(payload, 80) or "-", confirm_reason))
                    answer = CONFIRM_NO
                    if control is not None and hasattr(control, "ask"):
                        try:
                            answer = control.ask(question, [CONFIRM_YES, CONFIRM_NO], CONFIRM_NO,
                                                 context=str(task.get("reason", ""))[:200])
                        except Exception:
                            answer = CONFIRM_NO
                    if answer != CONFIRM_YES:
                        executed.append({"url": url, "param": param, "payload": payload,
                                         "verdict": "SKIPPED_NEEDS_CONFIRMATION", "reason": confirm_reason,
                                         "loop": loop_count})
                        emit("system", "⏭️ Test atlandı (onay yok): %s [%s] — %s" % (url[:70], param, confirm_reason))
                        continue
                    emit("system", "✅ Operatör onayladı: %s [%s]" % (url[:70], param))

                emit("strategist", "Test: %s [%s] ← payload %.60s" % (url[:80], param, payload or "-"))
                try:
                    response = active_scanner_callback(url, param, payload)
                except Exception as e:
                    response = {"error": str(e)}
                if not isinstance(response, dict):
                    response = {"error": "geçersiz yanıt"}
                # İstemci bütçesi doldu (run_custom_test → limit_reached). Eski sürümde bu kontrol
                # hiç eşleşmeyen bir metne bakıyordu; artık açık bayrak kullanılır.
                if response.get("limit_reached") or response.get("error") == "istek limiti":
                    emit("error", "AI istek bütçesi doldu; döngü sonlandırılıyor.")
                    executed.append({"url": url, "param": param, "payload": payload, "verdict": "RATE_LIMIT", "loop": loop_count})
                    loop_count = self.max_loops  # üst limit: dış döngüyü de bitir
                    break
                # Kod düzeyindeki koruma (safety_guard) probu GÖNDERMEDİ → Analyst çağrısı yapılmaz;
                # geçmişe yazılır ki Stratejist aynı probu tekrar önermesin.
                if response.get("blocked"):
                    blocked_verdict = "BLOCKED_SCOPE" if response.get("blocked") == "scope" else "BLOCKED_PAYLOAD"
                    block_reason = str(response.get("reason") or response.get("error") or "")[:200]
                    executed.append({"url": url, "param": param, "payload": payload,
                                     "verdict": blocked_verdict, "reason": block_reason, "loop": loop_count})
                    emit("error", "⛔ Prob gönderilmedi (%s): %s [%s] — %s" % (
                        "kapsam dışı" if blocked_verdict == "BLOCKED_SCOPE" else "güvensiz payload",
                        url[:70], param, block_reason[:120]))
                    continue

                # 4. ANALİZ (The Analyst) — her kanıt ayrı değerlendirilir
                verdict_raw = ""
                vobj = None
                try:
                    analysis_input = json.dumps({
                        "probe": {"url": url, "param": param, "payload": payload,
                                  "vuln_class": task.get("vuln_class", "other"),
                                  "reason": str(task.get("reason", ""))[:160]},
                        "response": {
                            "status": response.get("status"),
                            "body_length": response.get("body_length") or len(str(response.get("body", ""))),
                            "body_excerpt": _trim(str(response.get("body", "")), MAX_BODY_CHARS),
                            "headers_excerpt": _trim(str(response.get("headers", ""))[:400], 400),
                            "error": response.get("error"),
                        }
                    }, ensure_ascii=False, default=str)
                    verdict_res = self.analyst.think_json(analysis_input, want="object")
                    vobj = verdict_res.get("data")
                    verdict_raw = verdict_res.get("raw", "")
                    if verdict_res.get("fixed"):
                        emit("analyst", "Analist çıktısı bozuktu; düzeltici tek tekrar ile onarıldı.")
                except Exception as e:
                    verdict_raw = "Error: analyst exception %s" % e

                if vobj is None and not _is_llm_error(verdict_raw):
                    emit("analyst", "⚠️ Analist yanıtı ayrıştırılamadı; KARARSIZ sayıldı: %s [%s]" % (url[:60], param))
                verdict = (vobj or {}).get("verdict", "INCONCLUSIVE") if isinstance(vobj, dict) else "INCONCLUSIVE"
                executed.append({"url": url, "param": param, "payload": payload, "verdict": verdict, "loop": loop_count})

                if verdict == "VULNERABLE":
                    sev_map = {"critical": "KRİTİK", "high": "YÜKSEK", "medium": "ORTA", "low": "DÜŞÜK"}
                    sev = sev_map.get(str((vobj or {}).get("severity", "medium")).lower(), "YÜKSEK")
                    finding = {
                        "test": "AI Red Team (Strategist→Analyst)",
                        "severity": sev,
                        "title": "[AI-DOĞRULANMIŞ] %s — %s param=%s" % (
                            str(task.get("vuln_class") or "?").upper(), str(task.get("reason") or "")[:80], param),
                        "evidence": _trim("%s | kanıt: %s" % (
                            payload, (vobj or {}).get("evidence_quote", "")[:300]), 600),
                        "cwe": (vobj or {}).get("cwe") or "-",
                        "fix": "Girdi doğrulama + bağlama göre çıktı kodlama + parametreli sorgu uygulayın.",
                        "verdict_detail": vobj or {"raw": _trim(verdict_raw, 400)},
                        "summary": "%s %s (%s)" % (url[:90], param, sev),
                    }
                    verified_findings.append(finding)
                    emit("analyst", "✅ DOĞRULANDI (%s): %s" % (sev, finding["title"][:110]))
                else:
                    emit("analyst", "⬜ %s: %s [%s]" % (verdict, url[:70], param))

            # Küçük/yerel model modu: verimsiz turdan sonra bağımsız Mentor önerisi (PentAGI adviser uyarlaması)
            if (self.small_model_mode and not was_cancelled and loop_count < self.max_loops
                    and mentor_calls < 2):
                round_entries = [e for e in executed if e.get("loop") == loop_count]
                if not any(e.get("verdict") == "VULNERABLE" for e in round_entries):
                    mentor_calls += 1
                    mentor_ctx = json.dumps({
                        "target": target_url,
                        "round": loop_count,
                        "round_results": [{"url": e.get("url"), "param": e.get("param"),
                                           "payload": str(e.get("payload", ""))[:60], "verdict": e.get("verdict")}
                                          for e in round_entries][:12],
                        "coverage": build_coverage_matrix(initial_data, executed),
                    }, ensure_ascii=False, default=str)
                    advice = self.mentor.think(mentor_ctx)
                    if not _is_llm_error(advice):
                        mentor_advice = _trim(advice, 700)
                        emit("mentor", "🧭 Mentor önerisi: %s" % _trim(advice, 300))
                    else:
                        errors.append("Mentor LLM hatası: %s" % _trim(advice, 120))

        # 5. FİNAL RAPOR (The Reporter) — yönetici özeti + zincir + düzeltme
        narrative = ""
        narrative_err = ""
        if not was_cancelled and cancelled():
            was_cancelled = True
        if was_cancelled:
            emit("system", "⏹️ İptal edildi; nihai rapor yazılmadı, kısmi sonuçlar döndürülüyor.")
        else:
            emit("analyst", "Nihai rapor yazılıyor…")
        try:
            report_ctx = json.dumps({
                "target": target_url,
                "verified_findings": verified_findings,
                "deterministic_engine_findings": initial_data.get("static_findings", [])[:40],
                "executed_tests": len(executed),
                "attack_surface_summary": {
                    "pages": len((initial_data.get("attack_surface") or {}).get("pages", [])),
                    "forms": len((initial_data.get("attack_surface") or {}).get("forms", [])),
                },
            }, ensure_ascii=False, default=str)
            narrative = "" if was_cancelled else self.reporter.think(report_ctx)
            if _is_llm_error(narrative):
                narrative_err = narrative
                narrative = ""
        except Exception as e:
            narrative_err = "Error: reporter exception %s" % e

        if narrative:
            emit("analyst", "Rapor tamamlandı (%d karakter)." % len(narrative))

        return {
            "verified_findings": verified_findings,
            "loaded_skills": active_playbooks,
            "loops": loop_count,
            "tests_executed": len(executed),
            "executed_tests": executed,
            "narrative_report": narrative,
            "errors": errors + ([narrative_err] if narrative_err else []),
            "cancelled": was_cancelled,
            "steering_notes": list(steering_notes),
            "mentor_calls": mentor_calls,
            "role_models": dict(self.role_models),
            "small_model_mode": self.small_model_mode,
            "history": _history_from_executed(executed, loop_count),
            "coverage_matrix": build_coverage_matrix(initial_data, executed),
            "telemetry": self._telemetry_summary(),
        }
