import io
import os
import tempfile
import unittest
import urllib.error

import threat_intel as ti

KEV = {"vulnerabilities": [{"cveID": "CVE-2021-23017", "knownRansomwareCampaignUse": "Unknown"},
                           {"cveID": "CVE-2019-11043", "knownRansomwareCampaignUse": "Known"}]}


def nvd(*items):
    vulns = []
    for cid, score, sev in items:
        vulns.append({"cve": {"id": cid, "descriptions": [{"lang": "en", "value": "desc " + cid}],
                              "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev}}]}}})
    return {"vulnerabilities": vulns}


class ExtractTests(unittest.TestCase):
    def test_headers_meta_and_scripts(self):
        html = ('<meta name="generator" content="WordPress 6.2.2">'
                '<script src="/js/jquery-ui-1.12.1/jquery-ui.min.js"></script>'
                '<script src="https://cdn.test/ajax/libs/jquery/1.12.4/jquery.min.js"></script>'
                '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script>'
                '<script src="/static/app.js"></script>'
                '<script src="https://unpkg.test/react-dom@18.2.0/umd/react-dom.production.min.js"></script>')
        comps = ti.extract_components({"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f", "X-Powered-By": "PHP/7.4.3"}, html)
        got = {(c["key"], c["version"]) for c in comps}
        self.assertTrue({("apache", "2.4.41"), ("openssl", "1.1.1f"), ("php", "7.4.3"), ("wordpress", "6.2.2"),
                         ("jquery-ui", "1.12.1"), ("jquery", "1.12.4")} <= got)
        self.assertEqual(len(comps), ti.MAX_COMPONENTS)

    def test_meta_content_first_and_no_version(self):
        comps = ti.extract_components({"Server": "nginx"}, '<meta content="Drupal 10.1.5 (https://drupal.org)" name="generator">'
                                      '<script src="/vue.min.js"></script><script src="/vue/2.6.14/vue.min.js"></script>')
        self.assertEqual({(c["key"], c["version"]) for c in comps}, {("drupal", "10.1.5"), ("vue", "2.6.14")})


class RunTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        os.environ["WSS_HISTORY_DB"] = os.path.join(tempfile.mkdtemp(prefix="wss-ti-"), "c.sqlite3")
        self.urls = []
        self._orig = (ti._http_json, ti._osv_npm, ti.NVD_SPACING_NO_KEY)
        ti.NVD_SPACING_NO_KEY = 0

        def fake_http(url, data=None, headers=None, timeout=20):
            self.urls.append(url)
            if url == ti.KEV_URL:
                return KEV
            if "f5%3Anginx%3A1.18.0" in url:
                return nvd(("CVE-2021-23017", 7.7, "HIGH"), ("CVE-2021-3618", 7.4, "HIGH"))
            if "nginx%3Anginx%3A1.18.0" in url:
                raise urllib.error.HTTPError(url, 404, "nf", {}, io.BytesIO(b"{}"))
            if "php%3Aphp%3A7.4.3" in url:
                return nvd(("CVE-2019-11043", 9.8, "CRITICAL"))
            raise AssertionError("beklenmeyen URL: " + url)
        ti._http_json = fake_http
        ti._osv_npm = lambda name, version: [{"id": "GHSA-gxr4", "aliases": ["CVE-2020-11022"], "score": None,
                                              "severity": "MEDIUM", "summary": "xss", "source": "OSV"}]

    def tearDown(self):
        ti._http_json, ti._osv_npm, ti.NVD_SPACING_NO_KEY = self._orig
        os.environ.clear()
        os.environ.update(self._env)

    def test_findings_are_needs_validation_with_kev_and_no_target_leak(self):
        events = []
        findings, summary = ti.run_threat_intel(
            {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
            '<script src="/jquery-3.4.1.min.js"></script>', emit=lambda a, m: events.append(m))
        by = {f["component"]["name"]: f for f in findings}
        self.assertEqual(set(by), {"nginx", "PHP", "jquery"})
        self.assertTrue(all(f["verdict"] == "needs_validation" for f in findings))
        self.assertEqual(by["PHP"]["severity"], "KRİTİK")
        self.assertIn("CISA KEV", by["PHP"]["evidence"])
        self.assertIn("fidye yazılımı", by["PHP"]["evidence"])
        self.assertEqual(by["nginx"]["intel"]["kev_count"], 1)
        self.assertEqual(by["nginx"]["severity"], "YÜKSEK")
        self.assertEqual(summary["kev_matches"], 2)
        self.assertEqual(summary["errors"], [])
        for u in self.urls:
            self.assertTrue(u.startswith((ti.NVD_URL, ti.KEV_URL)), u)
            self.assertNotIn("target", u)
        self.assertTrue(any("tamam" in e for e in events))

    def test_second_run_uses_cache(self):
        ti.run_threat_intel({"Server": "nginx/1.18.0"})
        before = len(self.urls)
        _, summary = ti.run_threat_intel({"Server": "nginx/1.18.0"})
        self.assertEqual(len(self.urls), before)
        self.assertGreaterEqual(summary["cache_hits"], 2)

    def test_network_errors_are_soft(self):
        def boom(url, data=None, headers=None, timeout=20):
            raise urllib.error.URLError("offline")
        ti._http_json = boom
        findings, summary = ti.run_threat_intel({"X-Powered-By": "PHP/8.1.0"})
        self.assertEqual(findings, [])
        self.assertTrue(any("KEV" in e for e in summary["errors"]))
        self.assertTrue(any("PHP" in e for e in summary["errors"]))

    def test_nvd_call_cap(self):
        ti.MAX_NVD_CALLS, orig = 1, ti.MAX_NVD_CALLS
        try:
            _, summary = ti.run_threat_intel({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"})
        finally:
            ti.MAX_NVD_CALLS = orig
        self.assertTrue(any("sınırı" in e for e in summary["errors"]))

    def test_no_components(self):
        findings, summary = ti.run_threat_intel({"Server": "BaseHTTP/0.6 Python/3.12"}, "<p>hi</p>")
        self.assertEqual((findings, summary["components"]), ([], []))
        self.assertEqual(self.urls, [])


if __name__ == "__main__":
    unittest.main()
