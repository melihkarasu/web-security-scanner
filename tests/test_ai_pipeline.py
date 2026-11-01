"""Uçtan uca AI Red Team hattı testi (sahte LLM + yerel zayıf uygulama, tamamı süreç içinde).

Doğrulananlar: kapsam dışı ve yıkıcı problar hedefe hiç gönderilmez, Analyst yalnızca gönderilen
problar için çağrılır, LLM'e giden prompt'larda sır bulunmaz (maskeleme gerçekten devrededir).
"""
import http.client
import json
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer

import active_scan_engine as ase
import ai_connector
import server
from tests.fixtures.vuln_app import SECRET_AWS, SECRET_JWT_SIGNATURE, SECRET_SESSION, start_fixture_app
from tests.mock_llm import MockLLM


class AIPipelineE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_rate = ase.RATE_LIMIT_SECONDS
        ase.RATE_LIMIT_SECONDS = 0
        cls.app, cls.base = start_fixture_app()
        cls.other, cls.other_base = start_fixture_app()
        cls.mock = MockLLM(lambda: [
            {"url": cls.base + "/search", "param": "q", "payload": "<script>alert(1)</script>",
             "vuln_class": "xss", "reason": "reflected"},
            {"url": cls.other_base + "/search", "param": "q", "payload": "<b>x</b>",
             "vuln_class": "xss", "reason": "prompt-injected off-scope target"},
            {"url": cls.base + "/item", "param": "id", "payload": "1; DROP TABLE users--",
             "vuln_class": "sqli", "reason": "destructive"},
            {"url": cls.base + "/item", "param": "id", "payload": "1'", "vuln_class": "sqli", "reason": "error-based"},
        ])
        cls._orig_raw = ai_connector.AIProviderFactory._create_raw_connector
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(lambda cfg: cls.mock)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ScannerHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        ai_connector.AIProviderFactory._create_raw_connector = cls._orig_raw
        ase.RATE_LIMIT_SECONDS = cls._orig_rate
        for srv in (cls.httpd, cls.app, cls.other):
            srv.shutdown()
            srv.server_close()

    def post(self, path, payload):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        try:
            conn.request("POST", path, body=json.dumps(payload),
                         headers={"Content-Type": "application/json", "X-WSS-Token": server.API_TOKEN})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def test_ai_pipeline_guards_and_redaction(self):
        status, body = self.post("/api/active-confirm", {"url": self.base + "/", "confirmed": True})
        self.assertEqual(status, 200, body)
        self.app.request_log.clear()
        self.other.request_log.clear()

        status, result = self.post("/api/ai-scan", {"url": self.base + "/", "modules": [],
                                                    "ai_config": {"provider": "openai", "api_key": "test-not-real",
                                                                  "model": "mock"}})
        self.assertEqual(status, 200, result)
        self.assertTrue(result.get("success"), result)
        self.assertEqual(result["history"]["kind"], "ai")  # Faz 3: AI taraması geçmişe yazılır
        import scan_history
        stored = scan_history.get_scan(result["history"]["scan_id"])
        probe_log = stored["meta"]["ai"]["executed_tests"]
        self.assertTrue(any(t["verdict"] == "BLOCKED_PAYLOAD" for t in probe_log))  # probe günlüğü kalıcı
        self.assertIn("The Analyst", stored["meta"]["ai"]["telemetry_by_agent"])

        verdicts = {(t["param"], t["payload"]): t["verdict"] for t in result["ai_report"]["executed_tests"]}
        self.assertEqual(verdicts[("q", "<b>x</b>")], "BLOCKED_SCOPE")
        self.assertEqual(verdicts[("id", "1; DROP TABLE users--")], "BLOCKED_PAYLOAD")
        self.assertEqual(verdicts[("q", "<script>alert(1)</script>")], "VULNERABLE")
        self.assertEqual(verdicts[("id", "1'")], "VULNERABLE")
        self.assertEqual(len(result["findings"]), 2)

        # Engellenen problar hedeflere hiç ulaşmadı
        self.assertEqual(self.other.request_log, [])
        self.assertFalse(any("DROP" in urllib.parse.unquote_plus(p).upper() for p in self.app.request_log))

        # LLM'e giden hiçbir prompt'ta sır yok ve maskeleme gerçekten çalıştı
        joined = "\n".join(self.mock.prompts)
        for secret in (SECRET_SESSION, SECRET_AWS, SECRET_JWT_SIGNATURE):
            self.assertNotIn(secret, joined)
        self.assertIn("[REDACTED", joined)

        # Analyst yalnızca gerçekten gönderilen 2 prob için çağrıldı
        self.assertEqual(sum(1 for p in self.mock.prompts if "You are The Analyst" in p), 2)

        # Faz 1: kapsam matrisi, dürüst tur geçmişi ve telemetri döndürülür
        rep = result["ai_report"]
        self.assertIn("coverage_matrix", rep)
        self.assertGreaterEqual(rep["coverage_matrix"]["tested_count"], 2)
        self.assertTrue(all("loop" in t for t in rep["executed_tests"]))
        self.assertEqual(len(rep["history"]), rep["loops"])
        self.assertIn("telemetry", rep)
        self.assertGreaterEqual(rep["telemetry"]["total_calls"], 1)
        self.assertIn("The Analyst", rep["telemetry"]["by_agent"])

        chain = " ".join(e["message"] for e in result["thought_chain"])
        self.assertIn("kapsam dışı", chain)
        self.assertIn("güvensiz payload", chain)


if __name__ == "__main__":
    unittest.main()
