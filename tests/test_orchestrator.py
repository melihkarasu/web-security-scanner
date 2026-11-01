import json
import unittest

import ai_orchestrator as orch
from ai_connector import AIConnector


class PrioritizedSurfaceTests(unittest.TestCase):
    def test_keeps_tech_headers_params_even_when_many_pages(self):
        state = {
            "target": "http://t.test/",
            "technology_fingerprints": ["nginx/1.25", "PHP/8.2", "Laravel"],
            "response_headers": {"Server": "nginx", "Set-Cookie": "sid=1", "X-Frame-Options": "DENY",
                                 "Content-Type": "text/html"},
            "attack_surface": {
                "pages": ["http://t.test/p%d" % i for i in range(400)] + ["http://t.test/search?q=1&cat=2"],
                "forms": [{"action": "/login", "fields": ["user", "pass"]}],
            },
            "static_findings": [{"test": "hdr", "severity": "low", "title": "missing CSP"}],
        }
        out = orch._prioritized_surface(state, 1500)
        parsed = json.loads(out)
        self.assertLessEqual(len(out), 2200)
        self.assertIn("nginx/1.25", json.dumps(parsed.get("technologies")))
        self.assertIn("Set-Cookie", json.dumps(parsed.get("security_headers")))
        self.assertTrue(parsed.get("forms"))
        self.assertTrue(any("search?q=1" in p for p in parsed.get("parameterized_endpoints", [])))
        # Content-Type is not a security header -> excluded from the security_headers block
        self.assertNotIn("Content-Type", json.dumps(parsed.get("security_headers")))


class CoverageMatrixTests(unittest.TestCase):
    def test_matrix_classifies_and_lists_untested(self):
        state = {"attack_surface": {"pages": ["http://t.test/i?id=1&ref=2", "http://t.test/s?q=3"]}}
        executed = [
            {"url": "http://t.test/i", "param": "id", "payload": "1'", "verdict": "VULNERABLE", "loop": 1},
            {"url": "http://t.test/i", "param": "id", "payload": "1 OR 1", "verdict": "NOT_VULNERABLE", "loop": 1},
            {"url": "http://t.test/s", "param": "q", "payload": ";drop", "verdict": "BLOCKED_PAYLOAD", "loop": 1},
        ]
        m = orch.build_coverage_matrix(state, executed)
        by = {(r["endpoint"], r["param"]): r for r in m["tested"]}
        self.assertEqual(by[("http://t.test/i", "id")]["status"], "vulnerable")
        self.assertEqual(by[("http://t.test/i", "id")]["probes"], 2)
        self.assertEqual(by[("http://t.test/s", "q")]["status"], "blocked")
        self.assertEqual(m["tested_count"], 2)
        # ref and (i.id already tested) -> ref is untested; q already tested
        untested = {(u["endpoint"], u["param"]) for u in m["untested_sample"]}
        self.assertIn(("http://t.test/i?id=1&ref=2", "ref"), untested)


class HistoryTests(unittest.TestCase):
    def test_per_round_counts_differ(self):
        executed = [
            {"verdict": "VULNERABLE", "loop": 1}, {"verdict": "NOT_VULNERABLE", "loop": 1},
            {"verdict": "BLOCKED_SCOPE", "loop": 2},
        ]
        hist = orch._history_from_executed(executed, 2)
        self.assertEqual(len(hist), 2)
        self.assertIn("2 prob", hist[0]["result"])
        self.assertIn("1 doğrulanmış", hist[0]["result"])
        self.assertIn("1 prob", hist[1]["result"])
        self.assertIn("1 engellenmiş", hist[1]["result"])


class ThinkJsonFixerTests(unittest.TestCase):
    def test_think_json_uses_fixer_retry(self):
        class Flaky(AIConnector):
            def __init__(self):
                self.model = "flaky"; self._calls = 0
            def _chat_impl(self, prompt, system_prompt="", json_mode=False):
                self._calls += 1
                return "here is your answer: nonsense" if self._calls == 1 else '{"verdict":"VULNERABLE"}'
        agent = orch.AIAgent("The Analyst", "role", Flaky())
        res = agent.think_json("ctx", want="object")
        self.assertTrue(res["ok"])
        self.assertTrue(res["fixed"])
        self.assertEqual(res["data"]["verdict"], "VULNERABLE")


if __name__ == "__main__":
    unittest.main()
