import unittest
import urllib.parse

import active_scan_engine as ase
from tests.fixtures.vuln_app import start_fixture_app


class _FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_rate = ase.RATE_LIMIT_SECONDS
        ase.RATE_LIMIT_SECONDS = 0
        cls.app, cls.base = start_fixture_app()
        cls.other, cls.other_base = start_fixture_app()

    @classmethod
    def tearDownClass(cls):
        ase.RATE_LIMIT_SECONDS = cls._orig_rate
        for srv in (cls.app, cls.other):
            srv.shutdown()
            srv.server_close()

    def setUp(self):
        self.app.request_log.clear()
        self.other.request_log.clear()

    def client(self, budget=5):
        return ase.RateLimitedClient(scope_url=self.base + "/", max_requests=budget)


class ScopedClientTests(_FixtureCase):
    def test_in_scope_request_is_sent(self):
        c = self.client()
        r = c.get(self.base + "/item?id=1")
        self.assertEqual(r["status"], 200)
        self.assertEqual(c.request_count, 1)

    def test_off_scope_request_is_not_sent_or_counted(self):
        c = self.client()
        r = c.get(self.other_base + "/")
        self.assertEqual(r.get("blocked"), "scope")
        self.assertEqual(c.request_count, 0)
        self.assertEqual(self.other.request_log, [])

    def test_off_scope_redirect_not_followed(self):
        c = self.client()
        r = c.get(self.base + "/redirect?to=" + urllib.parse.quote(self.other_base + "/", safe=""))
        self.assertEqual(r["status"], 302)
        self.assertEqual(self.other.request_log, [])
        self.assertIn(self.other_base, r["headers"].get("Location", ""))

    def test_in_scope_redirect_followed(self):
        r = self.client().get(self.base + "/redirect?to=/item%3Fid%3D7")
        self.assertEqual(r["status"], 200)
        self.assertIn("Item 7", r["body"])

    def test_budget_enforced(self):
        c = self.client(budget=2)
        c.get(self.base + "/")
        c.get(self.base + "/")
        with self.assertRaises(StopIteration):
            c.get(self.base + "/")

    def test_unscoped_client_behaviour_unchanged(self):
        c = ase.RateLimitedClient()
        self.assertEqual(c.max_requests, ase.MAX_REQUESTS_PER_SCAN)
        self.assertEqual(c.get(self.other_base + "/")["status"], 200)


class RunCustomTestGuardTests(_FixtureCase):
    def test_destructive_payload_never_sent(self):
        c = self.client()
        r = ase.run_custom_test(c, self.base + "/item?id=1", "id", "1; DROP TABLE users--")
        self.assertEqual(r["blocked"], "payload")
        self.assertEqual(c.request_count, 0)
        self.assertEqual(self.app.request_log, [])

    def test_destructive_value_hidden_in_url_never_sent(self):
        c = self.client()
        r = ase.run_custom_test(c, self.base + "/item?id=1%3B%20DELETE%20FROM%20users", "q", "x")
        self.assertEqual(r["blocked"], "payload")
        self.assertEqual(self.app.request_log, [])

    def test_off_scope_probe_blocked(self):
        r = ase.run_custom_test(self.client(), self.other_base + "/search", "q", "<b>x</b>")
        self.assertEqual(r["blocked"], "scope")
        self.assertEqual(self.other.request_log, [])

    def test_limit_reached_is_explicit(self):
        c = self.client(budget=1)
        ase.run_custom_test(c, self.base + "/search", "q", "a")
        r = ase.run_custom_test(c, self.base + "/search", "q", "b")
        self.assertTrue(r.get("limit_reached"))
        self.assertEqual(r["error"], "istek limiti")

    def test_benign_probe_returns_evidence(self):
        r = ase.run_custom_test(self.client(), self.base + "/search?q=x", "q", "<script>alert(1)</script>")
        self.assertEqual(r["status"], 200)
        self.assertIn("<script>alert(1)</script>", r["body"])


if __name__ == "__main__":
    unittest.main()
