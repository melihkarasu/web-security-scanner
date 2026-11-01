import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

import ai_connector
import server


class _FakeConn(ai_connector.AIConnector):
    def __init__(self, cfg):
        self.model = "fake"
    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        return '{"status":"ok","answer":42}'


class AiJsonTestEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = ai_connector.AIProviderFactory._create_raw_connector
        ai_connector.AIProviderFactory._create_raw_connector = staticmethod(_FakeConn)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ScannerHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        ai_connector.AIProviderFactory._create_raw_connector = cls._orig
        cls.httpd.shutdown(); cls.httpd.server_close()

    def test_json_health_endpoint(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request("POST", "/api/ai-json-test",
                     body=json.dumps({"ai_config": {"provider": "openai", "api_key": "x", "model": "m"}}),
                     headers={"Content-Type": "application/json", "X-WSS-Token": server.API_TOKEN})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["json_quality"], "clean")
        self.assertIn("answer", data["keys_returned"])

    def test_requires_token(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request("POST", "/api/ai-json-test", body="{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse(); resp.read(); conn.close()
        self.assertEqual(resp.status, 401)


if __name__ == "__main__":
    unittest.main()
