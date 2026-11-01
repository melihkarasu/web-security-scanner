"""Faz 2 uçtan uca: arka plan AI işi, canlı olaylar, soru-cevap, iptal ve notlar (gerçek HTTP, sahte LLM)."""
import http.client
import json
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

import active_scan_engine as ase
import ai_connector
import server
from ai_connector import AIConnector
from tests.fixtures.vuln_app import start_fixture_app


class AsyncScriptedLLM(AIConnector):
    plan = []
    prompts = []
    lock = threading.Lock()
    strategist_calls = 0

    def __init__(self, cfg):
        self.model = "async-mock"

    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        cls = AsyncScriptedLLM
        with cls.lock:
            cls.prompts.append(prompt)
        if "You are The Strategist" in prompt:
            with cls.lock:
                cls.strategist_calls += 1
                first = cls.strategist_calls == 1
            return json.dumps(cls.plan if first else [])
        if "You are The Analyst" in prompt:
            vuln = "Results for" in prompt and "alert(1)" in prompt
            return json.dumps({"verdict": "VULNERABLE" if vuln else "NOT_VULNERABLE",
                               "severity": "high", "cwe": "CWE-79", "evidence_quote": "x"})
        if "You are The Reporter" in prompt:
            return "### Yönetici Özeti\nok"
        return "Scout notes."


def probe(base, path, param="q", payload="<script>alert(1)</script>"):
    return {"url": base + path, "param": param, "payload": payload, "vuln_class": "xss", "reason": "r"}


class AsyncAIPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_rate = ase.RATE_LIMIT_SECONDS
        ase.RATE_LIMIT_SECONDS = 0
        cls.app, cls.base = start_fixture_app()
        cls._orig_raw = ai_connector.AIProviderFactory._create_raw_connector
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(lambda cfg: AsyncScriptedLLM(cfg))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ScannerHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        status, body = cls.call("POST", "/api/active-confirm", {"url": cls.base + "/", "confirmed": True})
        assert status == 200, body

    @classmethod
    def tearDownClass(cls):
        ai_connector.AIProviderFactory._create_raw_connector = cls._orig_raw
        ase.RATE_LIMIT_SECONDS = cls._orig_rate
        for srv in (cls.httpd, cls.app):
            srv.shutdown()
            srv.server_close()

    @classmethod
    def call(cls, method, path, payload=None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=60)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-WSS-Token"] = server.API_TOKEN
        try:
            conn.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def setUp(self):
        AsyncScriptedLLM.plan = []
        AsyncScriptedLLM.prompts = []
        AsyncScriptedLLM.strategist_calls = 0
        self.app.request_log.clear()

    def start(self, plan, ask_timeout=30):
        AsyncScriptedLLM.plan = plan
        status, body = self.call("POST", "/api/ai-scan", {
            "url": self.base + "/", "modules": [], "async": True,
            "ai_config": {"provider": "openai", "api_key": "***", "model": "m", "ask_timeout": ask_timeout}})
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("job_id"))
        return body["job_id"]

    def poll(self, job_id, until=("done", "error", "cancelled"), timeout=60):
        since, events, last = 0, [], None
        t0 = time.time()
        while time.time() - t0 < timeout:
            status, view = self.call("GET", "/api/ai-status?job=%s&since=%d" % (job_id, since))
            self.assertEqual(status, 200, view)
            events.extend(view["events"])
            since = view["next_seq"]
            last = view
            if view["status"] in until or (until == "question" and view.get("pending_question")):
                return view, events
            time.sleep(0.1)
        self.fail("iş zamanında bitmedi: %r" % (last,))

    def test_async_job_streams_events_and_returns_result(self):
        job_id = self.start([probe(self.base, "/search")])
        view, events = self.poll(job_id)
        self.assertEqual(view["status"], "done")
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, sorted(set(seqs)))
        self.assertTrue(any("Aşama 1/3" in e["message"] for e in events))
        res = view["result"]
        self.assertTrue(res["success"])
        self.assertFalse(res["cancelled"])
        self.assertEqual(res["job_id"], job_id)
        self.assertEqual(len(res["findings"]), 1)
        self.assertIn("telemetry", res["ai_report"])

    def test_operator_says_no_sensitive_endpoint_never_hit(self):
        job_id = self.start([probe(self.base, "/account/delete", param="id", payload="1")])
        view, _ = self.poll(job_id, until="question")
        q = view["pending_question"]
        self.assertEqual(view["status"], "waiting_input")
        self.assertIn("/account/delete", q["text"])
        status, _ = self.call("POST", "/api/ai-answer", {"job_id": job_id, "question_id": "yanlis", "answer": "Hayır, atla"})
        self.assertEqual(status, 400)
        status, _ = self.call("POST", "/api/ai-answer", {"job_id": job_id, "question_id": q["id"], "answer": "Hayır, atla"})
        self.assertEqual(status, 200)
        view, _ = self.poll(job_id)
        verdicts = [t["verdict"] for t in view["result"]["ai_report"]["executed_tests"]]
        self.assertEqual(verdicts, ["SKIPPED_NEEDS_CONFIRMATION"])
        self.assertFalse(any(p.startswith("/account/delete") for p in self.app.request_log))

    def test_unanswered_question_times_out_to_safe_default(self):
        job_id = self.start([probe(self.base, "/account/delete", param="id", payload="1")], ask_timeout=1)
        view, events = self.poll(job_id)
        self.assertEqual(view["result"]["ai_report"]["executed_tests"][0]["verdict"], "SKIPPED_NEEDS_CONFIRMATION")
        self.assertTrue(any("güvenli seçenek" in e["message"] for e in events))
        self.assertFalse(any(p.startswith("/account/delete") for p in self.app.request_log))

    def test_operator_says_yes_probe_runs(self):
        job_id = self.start([probe(self.base, "/account/delete", param="id", payload="1")])
        view, _ = self.poll(job_id, until="question")
        self.call("POST", "/api/ai-answer", {"job_id": job_id, "question_id": view["pending_question"]["id"],
                                             "answer": "Evet, test et"})
        self.poll(job_id)
        self.assertTrue(any(p.startswith("/account/delete") for p in self.app.request_log))

    def test_cancel_job(self):
        job_id = self.start([probe(self.base, "/search", payload="a%d" % i) for i in range(4)])
        status, body = self.call("POST", "/api/ai-cancel", {"job_id": job_id})
        self.assertEqual(status, 200, body)
        view, _ = self.poll(job_id)
        self.assertEqual(view["status"], "cancelled")
        self.assertTrue(view["result"].get("cancelled"))
        status, body = self.call("POST", "/api/ai-cancel", {"job_id": job_id})
        self.assertFalse(body["success"])

    def test_note_reaches_strategist(self):
        job_id = self.start([])
        status, body = self.call("POST", "/api/ai-note", {"job_id": job_id, "note": "Sadece q parametresine odaklan"})
        self.assertEqual(status, 200, body)
        self.poll(job_id)
        strat = [p for p in AsyncScriptedLLM.prompts if "You are The Strategist" in p]
        self.assertTrue(strat and "Sadece q parametresine odaklan" in strat[0])

    def test_unknown_job_and_token_required(self):
        status, body = self.call("GET", "/api/ai-status?job=yok")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "JOB_NOT_FOUND")
        for method, path in (("GET", "/api/ai-status?job=x"), ("POST", "/api/ai-cancel"),
                             ("POST", "/api/ai-note"), ("POST", "/api/ai-answer")):
            status, _ = self.call(method, path, {} if method == "POST" else None, token=False)
            self.assertEqual(status, 401, path)


if __name__ == "__main__":
    unittest.main()
