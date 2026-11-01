"""Faz 3 uçtan uca: tarama geçmişi, fark raporu ve tehdit istihbaratı (gerçek HTTP, ağa çıkmadan)."""
import http.client
import json
import os
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer

import active_scan_engine as ase
import server
import threat_intel as ti
from tests.fixtures import vuln_app
from tests.fixtures.vuln_app import start_fixture_app

PHP_NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2019-11043",
                                        "descriptions": [{"lang": "en", "value": "php-fpm underflow"}],
                                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8,
                                                                                    "baseSeverity": "CRITICAL"}}]}}}]}


class HistoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env_db = os.environ.get("WSS_HISTORY_DB")
        os.environ["WSS_HISTORY_DB"] = os.path.join(tempfile.mkdtemp(prefix="wss-hapi-"), "h.sqlite3")
        cls._orig_rate = ase.RATE_LIMIT_SECONDS
        ase.RATE_LIMIT_SECONDS = 0
        cls._orig_ti = (ti._http_json, ti._osv_npm, ti.NVD_SPACING_NO_KEY)
        ti.NVD_SPACING_NO_KEY = 0
        cls.intel_urls = []

        def fake_http(url, data=None, headers=None, timeout=20):
            cls.intel_urls.append(url)
            if url == ti.KEV_URL:
                return {"vulnerabilities": [{"cveID": "CVE-2019-11043", "knownRansomwareCampaignUse": "Known"}]}
            if "php%3Aphp%3A7.4.3" in url:
                return PHP_NVD
            raise AssertionError("beklenmeyen URL: " + url)
        ti._http_json = fake_http
        ti._osv_npm = lambda name, version: []
        cls.app, cls.base = start_fixture_app()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ScannerHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        status, body = cls.call("POST", "/api/active-confirm", {"url": cls.base + "/", "confirmed": True})
        assert status == 200, body

    @classmethod
    def tearDownClass(cls):
        ti._http_json, ti._osv_npm, ti.NVD_SPACING_NO_KEY = cls._orig_ti
        ase.RATE_LIMIT_SECONDS = cls._orig_rate
        vuln_app.FIXTURE_STATE.update({"escape_search": False, "powered_by": None})
        for srv in (cls.httpd, cls.app):
            srv.shutdown()
            srv.server_close()
        if cls._env_db is None:
            os.environ.pop("WSS_HISTORY_DB", None)
        else:
            os.environ["WSS_HISTORY_DB"] = cls._env_db

    @classmethod
    def call(cls, method, path, payload=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=120)
        try:
            conn.request(method, path, body=json.dumps(payload) if payload is not None else None,
                         headers={"Content-Type": "application/json", "X-WSS-Token": server.API_TOKEN})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()

    def setUp(self):
        self.call("POST", "/api/history-delete", {"all": True})
        vuln_app.FIXTURE_STATE.update({"escape_search": False, "powered_by": None})
        del self.intel_urls[:]

    def active_scan(self, threat=False):
        query = urllib.parse.urlencode({"url": self.base + "/search?q=x", "modules": "xss"})
        if threat:
            query += "&threat_intel=1"
        status, body = self.call("POST", "/api/active-scan?" + query)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("success"), body)
        return body

    def test_fixed_vulnerability_shows_up_in_diff(self):
        r1 = self.active_scan()
        self.assertTrue(r1["history"]["diff"]["first_scan"])
        xss_titles = [f["title"] for f in r1["findings"]
                      if "xss" in (str(f.get("test", "")) + " " + str(f.get("title", ""))).lower()
                      and f.get("severity") not in ("BİLGİ",)]
        self.assertTrue(xss_titles, r1["findings"])
        vuln_app.FIXTURE_STATE["escape_search"] = True
        r2 = self.active_scan()
        diff = r2["history"]["diff"]
        self.assertFalse(diff["first_scan"])
        self.assertGreaterEqual(diff["counts"]["fixed"], 1)
        self.assertTrue(any(item["title"] in xss_titles for item in diff["fixed"]), diff)
        status, listing = self.call("GET", "/api/history?target=" + urllib.parse.quote(self.base + "/baska/yol"))
        self.assertEqual(status, 200)
        self.assertEqual([s["id"] for s in listing["scans"]], [r2["history"]["scan_id"], r1["history"]["scan_id"]])
        status, full = self.call("GET", "/api/history-diff?id=" + r2["history"]["scan_id"])
        self.assertEqual(status, 200)
        self.assertEqual(full["diff"]["base_scan_id"], r1["history"]["scan_id"])
        status, one = self.call("GET", "/api/history-scan?id=" + r1["history"]["scan_id"])
        self.assertEqual(status, 200)
        self.assertTrue(one["scan"]["findings"])
        self.assertIn("xss", one["scan"]["meta"].get("modules", {}))  # modül istatistikleri kalıcı
        status, deleted = self.call("POST", "/api/history-delete", {"target": self.base + "/"})
        self.assertEqual((status, deleted["deleted"]), (200, 2))
        self.assertEqual(self.call("GET", "/api/history")[1]["scans"], [])

    def test_threat_intel_only_when_requested(self):
        vuln_app.FIXTURE_STATE["powered_by"] = "PHP/7.4.3"
        r_off = self.active_scan(threat=False)
        self.assertNotIn("threat_intel", r_off)
        self.assertEqual(self.intel_urls, [])
        r_on = self.active_scan(threat=True)
        self.assertEqual(r_on["threat_intel"]["finding_count"], 1)
        intel = [f for f in r_on["findings"] if f.get("test") == ti.TEST_NAME]
        self.assertEqual(len(intel), 1)
        self.assertEqual(intel[0]["verdict"], "needs_validation")
        self.assertIn("PHP 7.4.3", intel[0]["title"])
        self.assertIn("CISA KEV", intel[0]["evidence"])
        self.assertTrue(self.intel_urls)
        for url in self.intel_urls:
            self.assertNotIn("127.0.0.1", url)

    def test_bad_requests(self):
        self.assertEqual(self.call("GET", "/api/history-scan?id=yok")[0], 404)
        self.assertEqual(self.call("GET", "/api/history-diff?id=yok")[0], 404)
        self.assertEqual(self.call("POST", "/api/history-delete", {})[0], 400)
        self.assertEqual(self.call("POST", "/api/history-delete", {"all": "true"})[0], 400)


if __name__ == "__main__":
    unittest.main()
