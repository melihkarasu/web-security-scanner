"""Reflected XSS modülü: kodlanan yansıma YÜKSEK sayılmamalı (önceden var olan yanlış pozitif düzeltmesi)."""
import unittest

import active_scan_engine as ase
from tests.fixtures import vuln_app
from tests.fixtures.vuln_app import start_fixture_app


class XssModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._rate = ase.RATE_LIMIT_SECONDS
        ase.RATE_LIMIT_SECONDS = 0
        cls.app, cls.base = start_fixture_app()

    @classmethod
    def tearDownClass(cls):
        ase.RATE_LIMIT_SECONDS = cls._rate
        vuln_app.FIXTURE_STATE["escape_search"] = False
        cls.app.shutdown()
        cls.app.server_close()

    def run_xss(self, escape):
        vuln_app.FIXTURE_STATE["escape_search"] = escape
        return ase.test_xss_reflected(ase.RateLimitedClient(), self.base + "/search?q=x")

    def test_constants_are_harmless(self):
        self.assertEqual(ase.XSS_BREAKOUT_SUFFIX, "'" + '"' + "><wzxtag>")
        self.assertNotIn("script", ase.XSS_BREAKOUT_SUFFIX.lower())

    def test_unencoded_breakout_is_high(self):
        high = [f for f in self.run_xss(False) if f["severity"] == "YÜKSEK"]
        self.assertEqual(len(high), 1)
        self.assertIn("wzxtag", high[0]["evidence"])
        self.assertTrue(high[0]["title"].startswith("Reflected XSS"))

    def test_encoded_reflection_is_only_info(self):
        findings = self.run_xss(True)
        self.assertFalse([f for f in findings if f["severity"] == "YÜKSEK"])
        self.assertTrue(any(f["severity"] == "BİLGİ" and "kodlanıyor" in f["title"] for f in findings))

    def test_non_reflecting_param_no_finding(self):
        findings = ase.test_xss_reflected(ase.RateLimitedClient(), self.base + "/redirect?to=/")
        self.assertFalse([f for f in findings if "Reflected" in f["title"] or "yansıması" in f["title"]])


if __name__ == "__main__":
    unittest.main()
