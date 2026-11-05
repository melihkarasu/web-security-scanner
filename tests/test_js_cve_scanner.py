import os
import tempfile
import unittest

import js_cve_scanner
import sast_engine


class JsCveScannerTests(unittest.TestCase):
    def test_evaluate_js_library_detects_vulnerable_and_clean_versions(self):
        vulns = js_cve_scanner.evaluate_js_library("jquery", "2.1.4", allow_network=False)
        self.assertTrue(vulns)
        cves = [c for v in vulns for c in v.get("cves", [])]
        self.assertIn("CVE-2015-9251", cves)
        self.assertIn("CVE-2020-11022", cves)
        self.assertEqual(js_cve_scanner.evaluate_js_library("jquery", "3.7.1", allow_network=False), [])

    def test_scan_file_for_js_cves_in_php_and_js_banner(self):
        php_code = '<html><head><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script></head></html>'
        f1 = js_cve_scanner.scan_file_for_js_cves("index.php", php_code, allow_network=False)
        self.assertEqual(len(f1), 1)
        self.assertEqual(f1[0]["rule_id"], "JS-CVE-001")
        self.assertIn("3.7.1", f1[0]["fix"])

        js_code = "/*! jQuery v3.3.1 | (c) JS Foundation */\nwindow.jQuery = {};"
        f2 = js_cve_scanner.scan_file_for_js_cves("js/vendor.js", js_code, allow_network=False)
        self.assertEqual(len(f2), 1)
        self.assertIn("CVE-2019-11358", f2[0]["title"])

    def test_sast_scan_directory_includes_retirejs_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "header.php"), "w", encoding="utf-8") as f:
                f.write('<script src="/assets/bootstrap-3.3.7.min.js"></script>\n')
            res = sast_engine.sast_scan_directory(tmp)
            self.assertTrue(res["success"])
            js_hits = [x for x in res["findings"] if x["rule_id"] == "JS-CVE-001"]
            self.assertEqual(len(js_hits), 1)
            self.assertIn("CVE-2018-14040", js_hits[0]["title"])


if __name__ == "__main__":
    unittest.main()
