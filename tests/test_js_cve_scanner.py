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



    def test_nextjs_november_2026_security_release_checks(self):
        pkg_json = '{"dependencies": {"next": "15.5.10", "react": "19.0.0"}}'
        f_pkg = js_cve_scanner.scan_file_for_js_cves("package.json", pkg_json, allow_network=False)
        self.assertTrue(any(x["rule_id"] == "NEXT-ADV-001" and "15.5.29" in x["fix"] for x in f_pkg))

        pkg_16 = '{"dependencies": {"next": "16.4.2"}}'
        f_pkg16 = js_cve_scanner.scan_file_for_js_cves("package.json", pkg_16, allow_network=False)
        self.assertTrue(any(x["rule_id"] == "NEXT-ADV-001" and "16.4.5" in x["fix"] for x in f_pkg16))

        pkg_patched = '{"dependencies": {"next": "16.4.5"}}'
        self.assertEqual(js_cve_scanner.scan_file_for_js_cves("package.json", pkg_patched, allow_network=False), [])

        code_cache = '"use cache";\nimport { unstable_cache } from "next/cache";\nexport async function getTenant(buf: Uint8Array) { return unstable_cache(async () => 1)(); }'
        f_code = js_cve_scanner.scan_file_for_js_cves("app/data.ts", code_cache, allow_network=False)
        rule_ids = {x["rule_id"] for x in f_code}
        self.assertIn("NEXT-ADV-002", rule_ids)
        self.assertIn("NEXT-ADV-003", rule_ids)

        code_edge = 'export const runtime = "edge";\nexport async function GET(req) { const res = NextResponse.next(); res.cookies.set("sid", "123"); return await fetch("https://example.com"); }'
        f_edge = js_cve_scanner.scan_file_for_js_cves("app/api/route.ts", code_edge, allow_network=False)
        edge_ids = {x["rule_id"] for x in f_edge}
        self.assertIn("NEXT-ADV-004", edge_ids)
        self.assertIn("NEXT-ADV-005", edge_ids)


if __name__ == "__main__":
    unittest.main()
