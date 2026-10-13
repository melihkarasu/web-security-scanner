import json
import time
from typing import List, Dict, Any, Optional
from ai_connector import AIProviderFactory

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


def _extract_json(text: str, want: str = "list"):
    """LLM çıktısından ilk dengeli JSON dizisini/cismını çıkarır."""
    text = text or ""
    opener, closer = ("[", "]") if want == "list" else ("{", "}")
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
                try:
                    return json.loads(text[start:i + 1])
                except Exception:
                    return None
    return None


class AIAgent:
    """Genel ajan yapısı."""
    def __init__(self, name: str, role_prompt: str, connector):
        self.name = name
        self.role_prompt = role_prompt
        self.connector = connector

    def think(self, context: str, user_input: str = "") -> str:
        full_prompt = f"{self.role_prompt}\n\nCONTEXT:\n{_trim(context, MAX_CONTEXT_CHARS)}\n\nINPUT: {user_input}"
        return self.connector.chat(full_prompt)


class AIOrchestrator:
    """
    Ajanlar arası döngüyü yöneten ve maliyet kontrolü yapan ana orkestratör.
    """
    def __init__(self, provider_config: dict, max_loops: int = 3, max_tests_per_loop: int = 4):
        self.connector = AIProviderFactory.create_connector(provider_config)
        self.max_loops = max_loops
        self.max_tests_per_loop = max_tests_per_loop

        self.scout = AIAgent(
            "The Scout",
            "You are The Scout, an elite web-application recon specialist in an autonomous red team. "
            "You are given REAL scan data: HTTP headers, technology fingerprints, crawled site map, "
            "discovered forms/parameters, and baseline active-scan findings. "
            "Produce a precise attack-surface assessment: (1) most attack-worthy parameters/endpoints "
            "with WHY (technology-specific risks), (2) likely vulnerability classes per entry point, "
            "(3) what baseline findings imply for chaining. Be specific: name exact URLs, parameters, "
            "technologies from the data. Never invent URLs that are not in the data. Max ~200 words.",
            self.connector
        )
        self.strategist = AIAgent(
            "The Strategist",
            "You are The Strategist, a red-team planner. Given the Scout's assessment, the real attack "
            "surface, and a history of already-executed tests, choose the NEXT set of concrete probes "
            "(max 4) that are NOT already in the history. Reply with ONLY a JSON array, no prose:\n"
            '[{"url": "<exact url from the data>", "param": "<exact param name>", "payload": "<harmless read-only probe payload>", '
            '"vuln_class": "sqli|xss|ssti|ssrf|open_redirect|idor|nosqli|other", "reason": "<one line>"}]\n'
            "Rules: payloads must be harmless and read-only (e.g. error-based markers, reflection markers "
            "like wzxqmk731, {{7*7}}, benign internal URLs for SSRF differentials, numeric ID swaps). "
            "No INSERT/UPDATE/DELETE, no destructive commands, no external canary domains you invented. "
            "If the surface is exhausted or nothing meaningful remains, reply with [].",
            self.connector
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
            self.connector
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
            self.connector
        )

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

    def orchestrate_scan(self, target_url: str, initial_data: Dict[str, Any], active_scanner_callback, progress_callback=None):
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

        context = json.dumps(initial_data, ensure_ascii=False, default=str)
        emit("system", "Bağlam hazır: %d sayfa, %d form, %d temel bulg." % (
            len((initial_data.get("attack_surface") or {}).get("pages", [])),
            len((initial_data.get("attack_surface") or {}).get("forms", [])),
            len(initial_data.get("static_findings", []))))

        while loop_count < self.max_loops:
            loop_count += 1

            # 1. KEŞİF (The Scout) — her turda biriken bulgularla yeniden değerlendirir
            emit("scout", "Tur %d/%d: Saldırı yüzeyi analiz ediliyor…" % (loop_count, self.max_loops))
            scout_input = ("Target: %s\nScan data:\n%s\nPrevious loop verdict: %s\nFindings so far: %s"
                           % (target_url, _trim(context, 6500), _trim(scout_report, 1200),
                              _trim(json.dumps([f.get("summary") for f in verified_findings], default=str), 1500)))
            scout_report = self.scout.think(scout_input)
            if _is_llm_error(scout_report):
                errors.append("Scout LLM hatası: %s" % _trim(scout_report, 120))
                break
            emit("scout", _trim(scout_report, 400))

            # 2. STRATEJİ (The Strategist)
            emit("strategist", "Tur %d: Hipotez planlanıyor…" % loop_count)
            strategy_ctx = ("Target: %s\nScout assessment: %s\nFull attack surface: %s\nAlready executed tests (DO NOT repeat):\n%s"
                            % (target_url, _trim(scout_report, 2000), _trim(context, 3500),
                               self._compress_history(executed)))
            plan_raw = self.strategist.think(strategy_ctx)
            if _is_llm_error(plan_raw):
                errors.append("Strategist LLM hatası: %s" % _trim(plan_raw, 120))
                break

            plan = _extract_json(plan_raw, "list")
            if plan is None:
                obj = _extract_json(plan_raw, "object")
                if isinstance(obj, dict):
                    for v in obj.values():
                        if isinstance(v, list):
                            plan = v
                            break
            if not isinstance(plan, list):
                # Tekrar dene: model düz metin döndürdüyse katı JSON hatırlatmasıyla
                emit("strategist", "Strateji çıktısı ayrıştırılamadı — katı JSON modunda tekrar deneniyor…")
                plan_raw = self.strategist.think(
                    strategy_ctx + "\n\nCRITICAL: your previous reply was not parseable JSON. "
                                   "Reply with ONLY the JSON array (use [] if no meaningful test remains). NO prose.")
                plan = _extract_json(plan_raw, "list")
                if plan is None:
                    obj = _extract_json(plan_raw, "object")
                    if isinstance(obj, dict):
                        for v in obj.values():
                            if isinstance(v, list):
                                plan = v
                                break
            if not isinstance(plan, list):
                emit("strategist", "İkinci denemede de ayrıştırılamadı; döngü burada sonlanıyor.")
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

                emit("strategist", "Test: %s [%s] ← payload %.60s" % (url[:80], param, payload or "-"))
                try:
                    response = active_scanner_callback(url, param, payload)
                except Exception as e:
                    response = {"error": str(e)}
                if isinstance(response, dict) and response.get("error") in ("istek limiti",):
                    emit("error", "İstek limitine ulaşıldı; döngü sonlandırılıyor.")
                    executed.append({"url": url, "param": param, "payload": payload, "verdict": "RATE_LIMIT"})
                    loop_count = self.max_loops  # üst limit: dış döngüyü de bitir
                    break

                # 4. ANALİZ (The Analyst) — her kanıt ayrı değerlendirilir
                verdict_raw = ""
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
                    verdict_raw = self.analyst.think(analysis_input)
                except Exception as e:
                    verdict_raw = "Error: analyst exception %s" % e

                vobj = _extract_json(verdict_raw, "object") if not _is_llm_error(verdict_raw) else None
                verdict = (vobj or {}).get("verdict", "INCONCLUSIVE") if isinstance(vobj, dict) else "INCONCLUSIVE"
                executed.append({"url": url, "param": param, "payload": payload, "verdict": verdict})

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

        # 5. FİNAL RAPOR (The Reporter) — yönetici özeti + zincir + düzeltme
        narrative = ""
        narrative_err = ""
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
            narrative = self.reporter.think(report_ctx)
            if _is_llm_error(narrative):
                narrative_err = narrative
                narrative = ""
        except Exception as e:
            narrative_err = "Error: reporter exception %s" % e

        if narrative:
            emit("analyst", "Rapor tamamlandı (%d karakter)." % len(narrative))

        return {
            "verified_findings": verified_findings,
            "loops": loop_count,
            "tests_executed": len(executed),
            "executed_tests": executed,
            "narrative_report": narrative,
            "errors": errors + ([narrative_err] if narrative_err else []),
            "history": [
                {"step": i + 1, "result": "%d test, toplam %d doğrulanmış bulgu" % (
                    min(len(executed), self.max_tests_per_loop), len(verified_findings))}
                for i in range(loop_count)
            ],
        }
