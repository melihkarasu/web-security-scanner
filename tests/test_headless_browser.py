"""Faz 5: gerçek tarayıcı motoru — kapsam vekili (Chromium gerekmez), Chromium testleri ve yalıtılmış servis."""
import base64
import http.client
import json
import os
import secrets
import socket
import threading
import unittest

import active_scan_engine as ase
import browser_service
import headless_browser as hb
from tests.fixtures import vuln_app
from tests.fixtures.vuln_app import start_fixture_app

CAPS = hb.capabilities(refresh=True)
HAS_CHROMIUM = bool(CAPS.get("available"))
KEY_ENV = "WSS_BROWSER_SERVICE_" + "TOKEN"


class _Fixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._rate = ase.RATE_LIMIT_SECONDS
        ase.RATE_LIMIT_SECONDS = 0
        cls.app, cls.base = start_fixture_app()
        cls.other, cls.other_base = start_fixture_app()

    @classmethod
    def tearDownClass(cls):
        ase.RATE_LIMIT_SECONDS = cls._rate
        vuln_app.FIXTURE_STATE["escape_search"] = False
        for srv in (cls.app, cls.other):
            srv.shutdown()
            srv.server_close()

    def setUp(self):
        del self.app.request_log[:]
        del self.other.request_log[:]
        vuln_app.FIXTURE_STATE["escape_search"] = False


def _via_proxy(port, method, url, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request(method, url, body=body, headers={"Connection": "close"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class ScopeProxyTests(_Fixtures):
    def test_in_scope_get_forwarded(self):
        proxy = hb.ScopedProxy(self.base + "/", budget=10).start()
        try:
            status, body = _via_proxy(proxy.port, "GET", self.base + "/item?id=7")
        finally:
            proxy.stop()
        self.assertEqual(status, 200)
        self.assertIn(b"Item 7", body)
        self.assertEqual(self.app.request_log, ["/item?id=7"])

    def test_off_scope_blocked_and_never_sent(self):
        proxy = hb.ScopedProxy(self.base + "/", budget=10).start()
        try:
            status, _ = _via_proxy(proxy.port, "GET", self.other_base + "/item?id=1")
            stats = proxy.stats()
        finally:
            proxy.stop()
        self.assertEqual(status, 403)
        self.assertEqual(self.other.request_log, [])
        self.assertEqual((stats["blocked_scope"], stats["requests"]), (1, 0))
        self.assertTrue(stats["blocked_origins"][0].startswith("http://127.0.0.1:"))

    def test_state_changing_methods_blocked(self):
        proxy = hb.ScopedProxy(self.base + "/", budget=10).start()
        try:
            status, _ = _via_proxy(proxy.port, "POST", self.base + "/account/delete?id=1", body=b"x=1")
        finally:
            proxy.stop()
        self.assertEqual(status, 405)
        self.assertEqual(self.app.request_log, [])

    def test_budget_enforced(self):
        proxy = hb.ScopedProxy(self.base + "/", budget=2).start()
        try:
            codes = [_via_proxy(proxy.port, "GET", self.base + "/item?id=%d" % i)[0] for i in range(3)]
            stats = proxy.stats()
        finally:
            proxy.stop()
        self.assertEqual(codes, [200, 200, 429])
        self.assertEqual(stats["blocked_budget"], 1)

    def test_connect_only_to_https_scope_origin(self):
        host_port = self.base.split("//", 1)[1]
        proxy = hb.ScopedProxy(self.base + "/", budget=5).start()  # http kapsamı: CONNECT yok
        try:
            self.assertEqual(_via_proxy(proxy.port, "CONNECT", host_port)[0], 403)
        finally:
            proxy.stop()
        proxy = hb.ScopedProxy("https://" + host_port + "/", budget=5).start()
        try:
            sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            sock.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (host_port, host_port)).encode())
            head = sock.recv(4096)
            self.assertIn(b" 200 ", head.split(b"\r\n", 1)[0])
            sock.sendall(("GET /item?id=9 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host_port).encode())
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            sock.close()
            self.assertIn(b"Item 9", data)
            self.assertEqual(_via_proxy(proxy.port, "CONNECT", "127.0.0.2:443")[0], 403)
        finally:
            proxy.stop()


class SurfaceAndHelpersTests(unittest.TestCase):
    def test_same_origin_links_and_forms_only(self):
        dom = ('<a href="/a?x=1">a</a><a href="https://evil.test/">e</a><a href="javascript:alert(1)">j</a>'
               '<form action="/s" method="post"><input name="q"><select name="k"></select></form>'
               '<form action="https://evil.test/p"><input name="z"></form><iframe src="/frame"></iframe>')
        s = hb.extract_surface(dom, "http://t.test/base/")
        self.assertEqual(s["links"], ["http://t.test/a?x=1", "http://t.test/frame"])
        self.assertEqual(s["forms"], [{"action": "http://t.test/s", "method": "post", "inputs": ["q", "k"]}])

    def test_split_hostport(self):
        self.assertEqual(hb._split_hostport("example.test:8443", 443), ("example.test", 8443))
        self.assertEqual(hb._split_hostport("[::1]:443", 443), ("::1", 443))
        self.assertEqual(hb._split_hostport("Host.Test", 443), ("host.test", 443))

    def test_proof_payload_passes_probe_guard(self):
        from safety_guard import validate_probe_payload
        self.assertEqual(validate_probe_payload(hb.XSS_PROOF_PAYLOAD.replace("NONCE", "ab12cd34")), (True, ""))

    def test_nonblocking_caps_never_waits(self):
        caps = hb.capabilities_nonblocking()
        self.assertIn("available", caps)


class UnavailableTests(_Fixtures):
    def test_missing_chromium_reported_and_scan_still_succeeds(self):
        old = os.environ.get("WSS_CHROMIUM_PATH")
        os.environ["WSS_CHROMIUM_PATH"] = "/nonexistent/chromium"
        try:
            self.assertFalse(hb.capabilities(refresh=True)["available"])
            ase.ETHICAL_GATE.confirm("127.0.0.1")
            res = ase.run_active_scan(self.base + "/search?q=x", ["xss"], options={"real_browser": True})
        finally:
            if old is None:
                os.environ.pop("WSS_CHROMIUM_PATH", None)
            else:
                os.environ["WSS_CHROMIUM_PATH"] = old
            hb.capabilities(refresh=True)
        self.assertTrue(res["success"])
        self.assertFalse(res["real_browser"]["available"])
        self.assertTrue(res["real_browser"]["error"])
        self.assertTrue(any(f["severity"] == "YÜKSEK" for f in res["findings"]))


@unittest.skipUnless(HAS_CHROMIUM, "Chromium (headless shell) bu makinede yok")
class ChromiumTests(_Fixtures):
    def test_spa_render_and_xss_proof(self):
        with hb.BrowserSession(self.base + "/") as bs:
            r = bs.render(self.base + "/spa")
            self.assertTrue(r["ok"], r["error"])
            self.assertIn(self.base + "/item?id=42", hb.extract_surface(r["dom"], self.base + "/spa")["links"])
            x = bs.confirm_xss(self.base + "/search?q=x", "q")
            self.assertTrue(x["executed"], x)
            self.assertTrue(base64.b64decode(x["screenshot"]).startswith(b"\x89PNG"))
            vuln_app.FIXTURE_STATE["escape_search"] = True
            x2 = bs.confirm_xss(self.base + "/search?q=x", "q")
            self.assertFalse(x2["executed"])
            self.assertIsNone(x2["screenshot"])

    def test_off_scope_subresource_blocked(self):
        with hb.BrowserSession(self.base + "/") as bs:
            bs.render(self.base + "/embed?src=" + self.other_base + "/pixel")
            stats = bs.stats()
        self.assertEqual(self.other.request_log, [])
        self.assertGreaterEqual(stats["blocked_scope"], 1)

    def test_out_of_scope_navigation_refused(self):
        with hb.BrowserSession(self.base + "/") as bs:
            r = bs.render(self.other_base + "/spa")
        self.assertFalse(r["ok"])
        self.assertEqual(self.other.request_log, [])

    def test_active_scan_confirms_xss_in_browser(self):
        ase.ETHICAL_GATE.confirm("127.0.0.1")
        res = ase.run_active_scan(self.base + "/search?q=x", ["xss"], options={"real_browser": True})
        high = [f for f in res["findings"] if f["test"] == "XSS" and f["severity"] == "YÜKSEK"]
        self.assertEqual(len(high), 1)
        self.assertTrue(high[0]["browser_proof"]["executed"])
        self.assertEqual(high[0]["verdict"], "confirmed")
        self.assertIn("Gerçek tarayıcı kanıtı", high[0]["evidence"])
        self.assertEqual((res["real_browser"]["xss_checks"], res["real_browser"]["xss_confirmed"]), (1, 1))
        state = ase.export_scan_state(self.base + "/", res.get("site_map"), res["findings"], forms=res.get("forms"))
        self.assertNotIn("iVBORw0KGgo", json.dumps(state))  # ekran görüntüsü LLM bağlamına girmez

    def test_active_scan_spa_discovery_feeds_attack_surface(self):
        ase.ETHICAL_GATE.confirm("127.0.0.1")
        res = ase.run_active_scan(self.base + "/spa", ["browser"], options={"real_browser": True})
        self.assertGreaterEqual(res["real_browser"]["spa"]["new_links"], 1)
        self.assertTrue(any(p.get("url") == self.base + "/item?id=42" and p.get("source") == "real_browser"
                            for p in res["site_map"]))
        self.assertTrue(any(f.get("source") == "real_browser" and f.get("action_url", "").endswith("/search")
                            for f in res["forms"]))
        state = ase.export_scan_state(self.base + "/spa", res["site_map"], res["findings"], forms=res["forms"])
        self.assertIn(self.base + "/item?id=42", state["attack_surface"]["pages"])

    def test_remote_service_mode(self):
        keys = ("WSS_BROWSER_SERVICE_URL", KEY_ENV, "WSS_BROWSER_SERVICE_TOKEN_FILE")
        old = {k: os.environ.get(k) for k in keys}
        os.environ.pop("WSS_BROWSER_SERVICE_TOKEN_FILE", None)
        os.environ[KEY_ENV] = secrets.token_urlsafe(16)
        server = browser_service.make_server("127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        os.environ["WSS_BROWSER_SERVICE_URL"] = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            caps = hb.capabilities(refresh=True)
            self.assertTrue(caps["available"] and caps["remote"], caps)
            with hb.open_session(self.base + "/") as session:
                self.assertIsInstance(session, hb.RemoteBrowserSession)
                x = session.confirm_xss(self.base + "/search?q=x", "q")
                self.assertTrue(x["executed"], x)
                st = session.stats()
            self.assertTrue(st["remote"])
            self.assertGreaterEqual(st["requests"], 1)
            good = os.environ[KEY_ENV]
            os.environ[KEY_ENV] = "wrong-" + good[:4]
            self.assertFalse(hb.capabilities(refresh=True)["available"])
            os.environ[KEY_ENV] = good
        finally:
            server.shutdown()
            server.server_close()
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            hb.capabilities(refresh=True)


if __name__ == "__main__":
    unittest.main()
