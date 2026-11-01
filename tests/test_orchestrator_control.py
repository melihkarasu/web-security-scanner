"""Faz 2 orkestratör kontrolleri: onay (ask), iptal, kullanıcı notları, ajan başına model, mentor."""
import json
import unittest

import ai_connector
import ai_orchestrator as orch
from ai_connector import AIConnector

INSTANCES = []
BASE = "http://t.test"
SURFACE = {"target": BASE + "/",
           "attack_surface": {"pages": [BASE + "/search?q=1", BASE + "/account/delete?id=1"], "forms": []},
           "response_headers": {}, "technology_fingerprints": [], "static_findings": []}


class ScriptedLLM(AIConnector):
    plans = []

    def __init__(self, cfg):
        self.model = (cfg or {}).get("model") or "default-model"
        self.prompts = []
        INSTANCES.append(self)

    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        self.prompts.append(prompt)
        if "You are The Strategist" in prompt:
            idx = sum(1 for i in INSTANCES for p in i.prompts if "You are The Strategist" in p) - 1
            return json.dumps(ScriptedLLM.plans[idx] if idx < len(ScriptedLLM.plans) else [])
        if "You are The Analyst" in prompt:
            verdict = "VULNERABLE" if "MARKER_HIT" in prompt else "NOT_VULNERABLE"
            return json.dumps({"verdict": verdict, "severity": "high", "cwe": "CWE-79", "evidence_quote": "x"})
        if "You are The Mentor" in prompt:
            return "- Try the untested parameter with a different vulnerability class."
        if "You are The Reporter" in prompt:
            return "### Yönetici Özeti\nok"
        return "Scout notes."


class Control:
    def __init__(self, answers=None, notes=None):
        self.answers = list(answers or [])
        self.notes = list(notes or [])
        self.questions = []
        self.cancel_now = False

    def is_cancelled(self):
        return self.cancel_now

    def pop_notes(self):
        notes, self.notes = self.notes, []
        return notes

    def ask(self, text, options, default, timeout=None, context=None):
        self.questions.append(text)
        return self.answers.pop(0) if self.answers else default


def probe(path, **extra):
    d = {"url": BASE + path, "param": "q", "payload": "x", "vuln_class": "xss", "reason": "r"}
    d.update(extra)
    return d


class OrchestratorControlTests(unittest.TestCase):
    def setUp(self):
        INSTANCES.clear()
        ScriptedLLM.plans = []
        self._orig = ai_connector.AIProviderFactory._create_raw_connector
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(lambda cfg: ScriptedLLM(cfg))
        self.calls = []
        self.cancel_after_first = None

    def tearDown(self):
        ai_connector.AIProviderFactory._create_raw_connector = self._orig

    def callback(self, url, param, payload):
        self.calls.append((url, param, payload))
        if self.cancel_after_first is not None:
            self.cancel_after_first.cancel_now = True
        body = ("MARKER_HIT " + payload) if "/search" in url else "ok"
        return {"status": 200, "body": body, "headers": "", "body_length": len(body)}

    def run_scan(self, cfg=None, control=None, max_loops=1):
        base_cfg = {"provider": "openai", "model": "default-model", "api_key": "***"}
        base_cfg.update(cfg or {})
        o = orch.AIOrchestrator(base_cfg, max_loops=max_loops)
        return o.orchestrate_scan(BASE + "/", json.loads(json.dumps(SURFACE)), self.callback, control=control)

    def prompts(self):
        return [p for i in INSTANCES for p in i.prompts]

    # --- onay (ask) ---
    def test_sensitive_probe_asks_and_skips_on_no(self):
        ScriptedLLM.plans = [[probe("/account/delete", param="id", payload="1")]]
        ctl = Control(answers=[orch.CONFIRM_NO])
        res = self.run_scan(control=ctl)
        self.assertEqual(len(ctl.questions), 1)
        self.assertIn("/account/delete", ctl.questions[0])
        self.assertEqual(self.calls, [])
        self.assertEqual(res["executed_tests"][0]["verdict"], "SKIPPED_NEEDS_CONFIRMATION")

    def test_sensitive_probe_runs_when_operator_confirms(self):
        ScriptedLLM.plans = [[probe("/account/delete", param="id", payload="1")]]
        self.run_scan(control=Control(answers=[orch.CONFIRM_YES]))
        self.assertEqual(len(self.calls), 1)

    def test_without_control_sensitive_probe_is_skipped_safely(self):
        ScriptedLLM.plans = [[probe("/account/delete", param="id", payload="1")]]
        res = self.run_scan(control=None)
        self.assertEqual(self.calls, [])
        self.assertEqual(res["executed_tests"][0]["verdict"], "SKIPPED_NEEDS_CONFIRMATION")

    def test_llm_needs_confirmation_flag_triggers_question(self):
        ScriptedLLM.plans = [[probe("/search", payload="<b>", needs_confirmation=True)]]
        ctl = Control(answers=[orch.CONFIRM_YES])
        res = self.run_scan(control=ctl)
        self.assertEqual(len(ctl.questions), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(res["executed_tests"][0]["verdict"], "VULNERABLE")

    def test_benign_probe_does_not_ask(self):
        ScriptedLLM.plans = [[probe("/search", payload="<b>")]]
        ctl = Control()
        self.run_scan(control=ctl)
        self.assertEqual(ctl.questions, [])
        self.assertEqual(len(self.calls), 1)

    def test_sensitive_pattern_boundaries(self):
        for url, expect in (("http://t/api/user/remove", True), ("http://t/logout", True),
                            ("http://t/x?action=delete", True), ("http://t/payment/confirm", True),
                            ("http://t/paypal-info", False), ("http://t/dropdown", False),
                            ("http://t/blocks", False), ("http://t/search", False)):
            self.assertEqual(bool(orch._needs_confirmation(url, "q", "x")), expect, url)

    # --- iptal ---
    def test_cancel_stops_loop_and_skips_reporter(self):
        ScriptedLLM.plans = [[probe("/search", payload="a%d" % i) for i in range(4)]]
        ctl = Control()
        self.cancel_after_first = ctl
        res = self.run_scan(control=ctl, max_loops=3)
        self.assertTrue(res["cancelled"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(res["narrative_report"], "")
        self.assertFalse(any("You are The Reporter" in p for p in self.prompts()))

    # --- kullanıcı notları ---
    def test_user_notes_reach_strategist(self):
        ScriptedLLM.plans = [[]]
        ctl = Control(notes=["Sadece q parametresine odaklan"])
        res = self.run_scan(control=ctl)
        strat = [p for p in self.prompts() if "You are The Strategist" in p]
        self.assertIn("USER STEERING NOTES", strat[0])
        self.assertIn("Sadece q parametresine odaklan", strat[0])
        self.assertEqual(res["steering_notes"], ["Sadece q parametresine odaklan"])

    # --- ajan başına model + telemetri ---
    def test_role_models_route_and_telemetry_reports_model(self):
        ScriptedLLM.plans = [[probe("/search")]]
        res = self.run_scan(cfg={"role_models": {"analyst": "fast-model", "scout": "bad model; rm -rf /"}})
        self.assertEqual(sorted(i.model for i in INSTANCES), ["default-model", "fast-model"])
        by = res["telemetry"]["by_agent"]
        self.assertEqual(by["The Analyst"]["model"], "fast-model")
        self.assertEqual(by["The Scout"]["model"], "default-model")
        self.assertEqual(res["role_models"], {"analyst": "fast-model"})

    # --- mentor (küçük model modu) ---
    def test_small_model_mode_mentor_after_unproductive_round(self):
        ScriptedLLM.plans = [[probe("/other")], [probe("/other", payload="y")], []]
        res = self.run_scan(cfg={"small_model_mode": True}, max_loops=2)
        self.assertEqual(sum(1 for p in self.prompts() if "You are The Mentor" in p), 1)
        strat = [p for p in self.prompts() if "You are The Strategist" in p]
        self.assertIn("MENTOR ADVICE", strat[1])
        self.assertEqual(res["mentor_calls"], 1)

    def test_mentor_off_by_default(self):
        ScriptedLLM.plans = [[probe("/other")], [probe("/other", payload="y")]]
        res = self.run_scan(max_loops=2)
        self.assertFalse(any("You are The Mentor" in p for p in self.prompts()))
        self.assertEqual(res["mentor_calls"], 0)


if __name__ == "__main__":
    unittest.main()
