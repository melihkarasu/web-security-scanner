import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

import server


class ServerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ScannerHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    def auth(self, extra=None):
        headers = {"X-WSS-Token": server.API_TOKEN}
        headers.update(extra or {})
        return headers

    def test_api_requires_valid_token(self):
        status, _, body = self.call("GET", "/api/status")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "WSS_TOKEN_GEREKLI")
        self.assertEqual(self.call("GET", "/api/status", {"X-WSS-Token": "wrong"})[0], 401)

    def test_api_with_header_or_bearer_token(self):
        self.assertEqual(self.call("GET", "/api/status", self.auth())[0], 200)
        self.assertEqual(self.call("GET", "/api/status", {"Authorization": "Bearer " + server.API_TOKEN})[0], 200)

    def test_dns_rebinding_host_rejected_even_for_static(self):
        for path in ("/", "/api/status"):
            status, _, _ = self.call("GET", path, self.auth({"Host": "attacker.example:%d" % self.port}))
            self.assertEqual(status, 403, path)
        self.assertEqual(self.call("GET", "/api/status", self.auth({"Host": "localhost:%d" % self.port}))[0], 200)

    def test_cross_origin_rejected_same_origin_allowed(self):
        self.assertEqual(self.call("GET", "/api/status", self.auth({"Origin": "https://attacker.example"}))[0], 403)
        self.assertEqual(self.call("GET", "/api/status", self.auth({"Sec-Fetch-Site": "cross-site"}))[0], 403)
        same = "http://127.0.0.1:%d" % self.port
        status = self.call("GET", "/api/status", self.auth({"Origin": same, "Sec-Fetch-Site": "same-origin"}))[0]
        self.assertEqual(status, 200)

    def test_csrf_style_ethics_confirm_blocked(self):
        payload = json.dumps({"url": "http://victim.example", "confirmed": True})
        status, _, _ = self.call("POST", "/api/active-confirm",
                                 {"Origin": "https://attacker.example", "Content-Type": "text/plain"}, payload)
        self.assertEqual(status, 403)
        status, _, _ = self.call("POST", "/api/active-confirm", {"Content-Type": "text/plain"}, payload)
        self.assertEqual(status, 401)
        self.assertFalse(server.ETHICAL_GATE.is_confirmed("victim.example"))

    def test_no_cors_headers_and_security_headers(self):
        for method, path in (("GET", "/api/status"), ("OPTIONS", "/api/ai-scan"), ("GET", "/")):
            _, headers, _ = self.call(method, path, self.auth())
            self.assertNotIn("access-control-allow-origin", headers, path)
            self.assertEqual(headers.get("x-frame-options"), "DENY", path)
            self.assertEqual(headers.get("x-content-type-options"), "nosniff", path)

    def test_scan_endpoints_are_post_only(self):
        for path in ("/api/active-scan?url=http://127.0.0.1:1/", "/api/ai-scan"):
            self.assertEqual(self.call("GET", path, self.auth())[0], 405, path)

    def test_index_injects_token_and_is_not_cached(self):
        status, headers, body = self.call("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(('<meta name="wss-token" content="%s">' % server.API_TOKEN).encode(), body)
        self.assertEqual(headers.get("cache-control"), "no-store")

    def test_static_allowlist(self):
        self.assertEqual(self.call("GET", "/js/app.js")[0], 200)
        self.assertEqual(self.call("GET", "/css/style.css")[0], 200)
        for path in ("/server.py", "/.git/config", "/redaction.py", "/tests/test_redaction.py", "/css/",
                     "/%2e%2e/etc/passwd", "/Dockerfile", "/strix_runs/"):
            self.assertEqual(self.call("GET", path)[0], 404, path)

    def test_healthz_without_token(self):
        status, _, body = self.call("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})


if __name__ == "__main__":
    unittest.main()
