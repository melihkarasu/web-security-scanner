"""Faz 4: salt-okunur güvenlik asistanı + ajan talimatı uçları (sahte LLM, gerçek HTTP)."""
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

import ai_connector
import security_assistant as sa
import server
from ai_connector import AIConnector


def _k(*parts):
    """Test API anahtarını çalışma zamanında üretir (kaynakta sır benzeri literal bulunmasın)."""
    return "-".join(("unit", "test") + parts)


def _cfg(**extra):
    c = {"provider": "openai", "api_key": _k("key"), "model": "m"}
    c.update(extra)
    return c


class EchoLLM(AIConnector):
    """Aldığı prompt'u ve sistem prompt'unu döndürür (maskeleme + bağlam testleri için)."""
    def __init__(self, cfg):
        self.model = "echo"
    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        return "SYS<<" + (system_prompt or "") + ">>\nPROMPT<<" + prompt + ">>"


class AssistantModuleTests(unittest.TestCase):
    def setUp(self):
        self._orig = ai_connector.AIProviderFactory._create_raw_connector
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(lambda cfg: EchoLLM(cfg))

    def tearDown(self):
        ai_connector.AIProviderFactory._create_raw_connector = self._orig

    def test_empty_question_rejected(self):
        self.assertFalse(sa.answer_question(_cfg(), "  ")["success"])

    def test_context_digest_masks_secrets(self):
        secret = "SUPER" + "SECRET" + "123"
        ctx = {"target": "http://t.test/", "findings": [
            {"test": "Headers", "severity": "YÜKSEK", "title": "Çerez sızıntısı",
             "evidence": "Set-Cookie: session=" + secret + "; HttpOnly", "cwe": "CWE-200", "fix": "HttpOnly"}]}
        digest = sa.build_context_digest(ctx)
        self.assertNotIn(secret, digest)
        self.assertIn("Çerez sızıntısı", digest)

    def test_answer_includes_system_rules_and_redacted_context(self):
        akia = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        ctx = {"findings": [{"title": "key leak", "evidence": "key " + akia + " found", "severity": "KRİTİK"}]}
        res = sa.answer_question(_cfg(), "Bu bulguyu açıkla", context=ctx)
        self.assertTrue(res["success"])
        self.assertIn("read-only, defensive security assistant", res["answer"])
        self.assertIn("UNTRUSTED DATA", res["answer"])
        self.assertNotIn(akia, res["answer"])  # bağlam maskelendi

    def test_history_is_included_bounded(self):
        history = [{"role": "user", "content": "q%d" % i} for i in range(20)]
        res = sa.answer_question(_cfg(), "son soru", context={"findings": []}, history=history)
        self.assertIn("q19", res["answer"])
        self.assertNotIn("q0:", res["answer"])  # yalnızca son N tur

    def test_llm_error_surfaced(self):
        class Boom(AIConnector):
            def __init__(self, cfg): self.model = "b"
            def _chat_impl(self, prompt, system_prompt="", json_mode=False): return "Error: provider down"
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(lambda cfg: Boom(cfg))
        res = sa.answer_question(_cfg(), "soru", context={})
        self.assertFalse(res["success"])
        self.assertIn("provider down", res["error"])


class AssistantEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = ai_connector.AIProviderFactory._create_raw_connector
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(lambda cfg: EchoLLM(cfg))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ScannerHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        ai_connector.AIProviderFactory._create_raw_connector = cls._orig
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, method, path, payload=None, with_token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        headers = {"Content-Type": "application/json"}
        if with_token:
            headers["X-WSS-Token"] = server.API_TOKEN
        try:
            conn.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def test_chat_endpoint(self):
        status, body = self.call("POST", "/api/ai-chat", {
            "ai_config": _cfg(),
            "question": "En kritik bulgu ne?",
            "context": {"findings": [{"title": "SQLi", "severity": "KRİTİK"}]}})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["success"])
        self.assertIn("SQLi", body["answer"])

    def test_chat_requires_token(self):
        self.assertEqual(self.call("POST", "/api/ai-chat", {}, with_token=False)[0], 401)

    def test_chat_rejects_empty_question(self):
        status, body = self.call("POST", "/api/ai-chat", {"ai_config": _cfg(), "question": ""})
        self.assertEqual(status, 400)
        self.assertFalse(body["success"])

    def test_agent_prompts_endpoint(self):
        status, body = self.call("GET", "/api/ai-agent-prompts")
        self.assertEqual(status, 200, body)
        self.assertEqual(set(body["defaults"]), {"scout", "strategist", "analyst", "reporter", "mentor"})
        self.assertIn("The Scout", body["defaults"]["scout"])
        self.assertTrue(body["locked_note"])

    def test_agent_prompts_requires_token(self):
        self.assertEqual(self.call("GET", "/api/ai-agent-prompts", with_token=False)[0], 401)


if __name__ == "__main__":
    unittest.main()
