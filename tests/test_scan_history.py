import os
import sqlite3
import tempfile
import time
import unittest

import scan_history as sh


def fnd(title, severity="ORTA", test="Headers", url="", cwe="CWE-693", evidence="x", **extra):
    d = {"title": title, "severity": severity, "test": test, "url": url, "cwe": cwe, "evidence": evidence}
    d.update(extra)
    return d


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self.tmp = tempfile.mkdtemp(prefix="wss-hist-")
        os.environ["WSS_HISTORY_DB"] = os.path.join(self.tmp, "sub", "h.sqlite3")
        os.environ.pop("WSS_HISTORY", None)
        os.environ.pop("WSS_HISTORY_RETENTION_DAYS", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_record_and_diff_new_fixed_persisting(self):
        t = "http://T.test:80/app?x=1"
        r1 = sh.record_scan("active", t, [fnd("Eksik CSP"), fnd("XSS yansıması", "YÜKSEK", "XSS", url="http://t.test/search", cwe="CWE-79")])
        self.assertTrue(r1["diff"]["first_scan"])
        self.assertEqual(r1["diff"]["counts"]["new"], 2)
        r2 = sh.record_scan("active", "http://t.test/", [fnd("Eksik CSP"), fnd("Açık yönlendirme", "ORTA", "Redirect", cwe="CWE-601")])
        c = r2["diff"]["counts"]
        self.assertEqual((c["new"], c["fixed"], c["persisting"]), (1, 1, 1))
        self.assertEqual(r2["diff"]["fixed"][0]["title"], "XSS yansıması")
        self.assertEqual(r2["target_key"], "http://t.test:80")

    def test_kinds_are_compared_separately(self):
        sh.record_scan("active", "http://k.test/", [fnd("A")])
        r = sh.record_scan("ai", "http://k.test/", [fnd("B")])
        self.assertTrue(r["diff"]["first_scan"])

    def test_ai_titles_with_different_reasons_share_fingerprint(self):
        a = {"title": "[AI-DOĞRULANMIŞ] SQLI — single quote error param=id", "cwe": "CWE-89",
             "summary": "http://t.test/item?id=1 id (YÜKSEK)"}
        b = {"title": "[AI-DOĞRULANMIŞ] SQLI — boolean differential confirms param=id", "cwe": "CWE-89",
             "summary": "http://t.test/item?id=2 id (YÜKSEK)"}
        other_param = dict(a, title="[AI-DOĞRULANMIŞ] SQLI — x param=q")
        self.assertEqual(sh.finding_fingerprint(a), sh.finding_fingerprint(b))
        self.assertNotEqual(sh.finding_fingerprint(a), sh.finding_fingerprint(other_param))

    def test_digits_in_titles_do_not_break_persistence(self):
        self.assertEqual(sh.finding_fingerprint(fnd("nginx 1.18.0 — 12 kayıt")),
                         sh.finding_fingerprint(fnd("nginx 1.20.1 — 9 kayıt")))

    def test_secrets_masked_before_storage(self):
        r = sh.record_scan("active", "http://s.test/", [fnd("Çerez", evidence="Set-Cookie: session=SUPERSECRET123; HttpOnly")])
        raw = sqlite3.connect(os.environ["WSS_HISTORY_DB"]).execute("SELECT findings_json FROM scans").fetchone()[0]
        self.assertNotIn("SUPERSECRET123", raw)
        self.assertIn("REDACTED", raw)
        self.assertIsNotNone(sh.get_scan(r["scan_id"]))

    def test_file_permissions(self):
        sh.record_scan("active", "http://p.test/", [])
        path = os.environ["WSS_HISTORY_DB"]
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)

    def test_list_delete_and_explicit_diff(self):
        a = sh.record_scan("active", "http://d.test/", [fnd("A")])
        b = sh.record_scan("active", "http://d.test/", [fnd("A"), fnd("B")])
        sh.record_scan("active", "http://other.test/", [fnd("C")])
        self.assertEqual([s["id"] for s in sh.list_scans(target="http://d.test/x")], [b["scan_id"], a["scan_id"]])
        d = sh.diff_scans(b["scan_id"], a["scan_id"])
        self.assertEqual([f["title"] for f in d["new"]], ["B"])
        self.assertEqual(sh.delete_scan(a["scan_id"]), 1)
        self.assertEqual(sh.delete_target("http://d.test/"), 1)
        self.assertEqual(len(sh.list_scans()), 1)
        self.assertEqual(sh.delete_all(), 1)

    def test_retention_prunes_old_scans(self):
        r = sh.record_scan("active", "http://r.test/", [fnd("A")])
        conn = sqlite3.connect(os.environ["WSS_HISTORY_DB"])
        conn.execute("UPDATE scans SET created_at = ? WHERE id = ?", (int(time.time()) - 40 * 86400, r["scan_id"]))
        conn.commit()
        conn.close()
        self.assertEqual(sh.prune(), 1)
        self.assertIsNone(sh.get_scan(r["scan_id"]))

    def test_disabled_history_records_nothing(self):
        os.environ["WSS_HISTORY"] = "0"
        self.assertIsNone(sh.record_scan("active", "http://x.test/", [fnd("A")]))
        self.assertEqual(sh.list_scans(), [])
        self.assertFalse(os.path.exists(os.environ["WSS_HISTORY_DB"]))
        sh.cache_set("k", {"v": 1})
        self.assertEqual(sh.cache_get("k", 60), {"v": 1})

    def test_cache_ttl(self):
        sh.cache_set("kev", {"CVE-1": {}})
        self.assertEqual(sh.cache_get("kev", 3600), {"CVE-1": {}})
        self.assertIsNone(sh.cache_get("kev", -1))


if __name__ == "__main__":
    unittest.main()
