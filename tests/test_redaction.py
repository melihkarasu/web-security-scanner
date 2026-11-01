import time
import unittest

from redaction import MASK, redact_obj, redact_text

JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


class RedactionTests(unittest.TestCase):
    def test_jwt_keeps_header_masks_payload_and_signature(self):
        out = redact_text("jwt " + JWT)
        self.assertIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[REDACTED_JWT_PAYLOAD]", out)
        self.assertNotIn("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", out)
        self.assertNotIn("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ", out)

    def test_unsigned_jwt_keeps_empty_signature(self):
        out = redact_text("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.")
        self.assertEqual(out, "eyJhbGciOiJub25lIn0.[REDACTED_JWT_PAYLOAD].")

    def test_authorization_header(self):
        self.assertIn('"Authorization": "Bearer [REDACTED]"',
                      redact_text('{"Authorization": "Bearer abcdef0123456789secret"}'))
        self.assertEqual(redact_text("Authorization: Basic dXNlcjpwYXNz"), "Authorization: Basic [REDACTED]")

    def test_authorization_with_jwt_keeps_alg(self):
        out = redact_text("Authorization: Bearer " + JWT)
        self.assertIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[REDACTED_JWT_PAYLOAD]", out)
        self.assertNotIn("SflKxwRJ", out)

    def test_set_cookie_keeps_names_and_flags(self):
        out = redact_text('{"Set-Cookie": "session=SUPERSECRET123; Path=/; HttpOnly; Secure; SameSite=Lax"}')
        self.assertIn("session=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax", out)
        self.assertNotIn("SUPERSECRET123", out)

    def test_multiple_cookies_and_expires(self):
        out = redact_text("Set-Cookie: a=1111; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, b=2222; HttpOnly")
        self.assertNotIn("1111", out)
        self.assertNotIn("2222", out)
        self.assertIn("Expires=Wed, 21 Oct 2026 07:28:00 GMT", out)

    def test_vendor_tokens(self):
        samples = ["AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "xoxb-1234567890-abcdefghij", "AIza" + "B" * 35,
                   "sk_live_" + "c" * 24, "sk-ant-api03-" + "d" * 30, "sk-proj-" + "e" * 30, "glpat-" + "f" * 20]
        for raw in samples:
            out = redact_text("x %s y" % raw)
            self.assertNotIn(raw, out)
            self.assertIn("REDACTED", out)

    def test_private_key_full_and_truncated(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\nABCDEF==\n"
               "-----END RSA PRIVATE KEY-----")
        out = redact_text(pem)
        self.assertNotIn("MIIEow", out)
        self.assertIn("-----END RSA PRIVATE KEY-----", out)
        out2 = redact_text("-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC")
        self.assertNotIn("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", out2)

    def test_connection_string_password(self):
        out = redact_text("DATABASE_URL=postgres://app:S3cr3tPass@db:5432/prod")
        self.assertNotIn("S3cr3tPass", out)
        self.assertIn("postgres://app:[REDACTED]@db:5432/prod", out)

    def test_hardcoded_literals_masked_but_code_semantics_kept(self):
        code = ('password = "hunter2hunter2"\napi_key: \'abc123xyz\'\nuser = request.form["password"]\n'
                'SECRET_KEY = os.environ.get("SECRET_KEY")\n')
        out = redact_text(code)
        self.assertIn('password = "[REDACTED]"', out)
        self.assertNotIn("hunter2hunter2", out)
        self.assertNotIn("abc123xyz", out)
        self.assertIn('request.form["password"]', out)
        self.assertIn('os.environ.get("SECRET_KEY")', out)

    def test_env_file_lines(self):
        out = redact_text("export OPENAI_API_KEY=abcdefghijkl\nDEBUG=true\nDB_PASSWORD=pa55word!")
        self.assertNotIn("abcdefghijkl", out)
        self.assertNotIn("pa55word!", out)
        self.assertIn("DEBUG=true", out)

    def test_query_and_hidden_inputs(self):
        out = redact_text('<a href="/cb?access_token=tok123456&x=1">x</a>'
                          '<input type="hidden" name="csrf_token" value="abcdef123456">')
        self.assertNotIn("tok123456", out)
        self.assertNotIn("abcdef123456", out)
        self.assertIn("x=1", out)

    def test_benign_text_unchanged(self):
        for s in ("{{7*7}}", "<script>alert(1)</script>", "' OR '1'='1", "Strict-Transport-Security: max-age=31536000",
                  "http://172.17.0.1:8088/search?q=test", "Set-Cookie flags: HttpOnly, Secure"):
            self.assertEqual(redact_text(s), s)

    def test_redact_obj_dict_and_headers(self):
        obj = {"headers": {"Set-Cookie": "sid=XYZ987654; HttpOnly", "Authorization": "Bearer abcdefgh",
                           "Content-Type": "text/html"},
               "body": "<p>AKIAIOSFODNN7EXAMPLE</p>", "list": ["ok", 'password="p4ssw0rd!!"'], "n": 5}
        out = redact_obj(obj)
        self.assertEqual(out["headers"]["Set-Cookie"], "sid=[REDACTED]; HttpOnly")
        self.assertEqual(out["headers"]["Authorization"], MASK)
        self.assertEqual(out["headers"]["Content-Type"], "text/html")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out["body"])
        self.assertNotIn("p4ssw0rd!!", out["list"][1])
        self.assertEqual(out["n"], 5)
        self.assertEqual(obj["headers"]["Authorization"], "Bearer abcdefgh")

    def test_non_string_passthrough(self):
        self.assertIsNone(redact_text(None))
        self.assertEqual(redact_text(""), "")

    def test_large_input_is_fast(self):
        blob = ("a" * 5000 + ".") * 40 + "password" * 2000 + "eyJ" * 3000
        started = time.time()
        redact_text(blob)
        self.assertLess(time.time() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
