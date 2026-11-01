"""Uyarlanabilir parametre geri dönüşü (temperature / response_format), Anthropic sıcaklık, Bedrock SigV4 yolu."""
import io
import json
import unittest
import urllib.error

import ai_connector as m


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Scripted:
    """_urlopen_with_retry yerine geçer: sıradaki adımı döner ya da HTTPError fırlatır; istekleri kaydeder."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.bodies, self.urls, self.headers = [], [], []

    def __call__(self, req, timeout=None, retries=None):
        self.bodies.append(json.loads(req.data.decode("utf-8")) if req.data else None)
        self.urls.append(req.full_url)
        self.headers.append(dict(req.header_items()))
        kind, payload = self.steps.pop(0)
        if kind == "err":
            code, msg = payload
            raise urllib.error.HTTPError(req.full_url, code, "err", {}, io.BytesIO(msg.encode()))
        return _Resp(json.dumps(payload).encode())


def _k(*parts):
    return "-".join(parts)


OK_CHAT = {"choices": [{"message": {"content": "{}"}}]}


class AdaptiveParamTests(unittest.TestCase):
    def setUp(self):
        self.orig = m._urlopen_with_retry

    def tearDown(self):
        m._urlopen_with_retry = self.orig

    def use(self, steps):
        fake = Scripted(steps)
        m._urlopen_with_retry = fake
        return fake

    def test_anthropic_never_sends_temperature(self):
        fake = self.use([("ok", {"content": [{"type": "text", "text": "ok"}]})])
        conn = m.AIProviderFactory.create_connector({"provider": "anthropic", "model": "claude-haiku-5-5",
                                                     "api_key": _k("unit", "a")})
        self.assertEqual(conn.chat("hi"), "ok")
        self.assertNotIn("temperature", fake.bodies[0])

    def test_openai_compatible_drops_rejected_temperature_and_remembers(self):
        fake = self.use([("err", (400, '{"error":{"message":"Unsupported value: temperature"}}')),
                         ("ok", OK_CHAT), ("ok", OK_CHAT)])
        conn = m.AIProviderFactory.create_connector({"provider": "openai", "model": "o-model",
                                                     "api_key": _k("unit", "o"), "base_url": "http://x.invalid/v1"})
        self.assertEqual(conn.chat("hi"), "{}")
        self.assertIn("temperature", fake.bodies[0])
        self.assertNotIn("temperature", fake.bodies[1])
        conn.chat("again")
        self.assertNotIn("temperature", fake.bodies[2])

    def test_json_mode_rejected_falls_back_to_prompt_json(self):
        ok = {"choices": [{"message": {"content": '{"verdict":"NOT_VULNERABLE"}'}}]}
        fake = self.use([("err", (400, "response_format json_object is not supported by this model")), ("ok", ok)])
        conn = m.AIProviderFactory.create_connector({"provider": "openai", "model": "local",
                                                     "api_key": _k("unit", "o"), "base_url": "http://x.invalid/v1"})
        res = conn.chat_json("q", want="object")
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["verdict"], "NOT_VULNERABLE")
        self.assertIn("response_format", fake.bodies[0])
        self.assertNotIn("response_format", fake.bodies[1])

    def test_unrelated_400_is_not_retried(self):
        fake = self.use([("err", (400, '{"error":"model not found"}'))])
        conn = m.AIProviderFactory.create_connector({"provider": "openai", "model": "x",
                                                     "api_key": _k("unit", "o"), "base_url": "http://x.invalid/v1"})
        self.assertTrue(conn.chat("hi").startswith("Error: OpenAI-compatible HTTP 400"))
        self.assertEqual(len(fake.bodies), 1)

    def test_azure_and_openrouter_use_adaptive_path(self):
        ok = {"choices": [{"message": {"content": "ok"}}]}
        for cfg in ({"provider": "azure", "api_key": _k("unit", "z"), "endpoint": "https://r.openai.azure.com",
                     "deployment": "d"},
                    {"provider": "openrouter", "api_key": _k("unit", "r"), "model": "m"}):
            fake = self.use([("err", (400, "response_format not supported")), ("ok", ok)])
            conn = m.AIProviderFactory.create_connector(cfg)
            self.assertEqual(conn.chat("hi", json_mode=True), "ok", cfg["provider"])
            self.assertNotIn("response_format", fake.bodies[1])

    def test_bedrock_double_encodes_model_id_and_drops_temperature(self):
        fake = self.use([("err", (400, '{"message":"temperature is deprecated for this model"}')),
                         ("ok", {"content": [{"type": "text", "text": "ok"}]})])
        conn = m.AIProviderFactory.create_connector({"provider": "bedrock", "access_key": "AKIDEXAMPLE",
                                                     "secret_key": _k("s", "k"), "region": "us-east-1",
                                                     "model_id": "anthropic.claude-sonnet-x-v1:0"})
        inner = conn._inner
        seen = []
        orig_sign = inner._sigv4_headers

        def spy(host, canonical_uri, body, when=None):
            seen.append(canonical_uri)
            return orig_sign(host, canonical_uri, body, when)
        inner._sigv4_headers = spy
        self.assertEqual(conn.chat("hi"), "ok")
        self.assertIn("v1%3A0/invoke", fake.urls[0])
        self.assertTrue(seen[0].endswith("v1%253A0/invoke"), seen[0])
        self.assertIn("temperature", fake.bodies[0])
        self.assertNotIn("temperature", fake.bodies[1])
        self.assertNotEqual(fake.headers[0].get("Authorization"), fake.headers[1].get("Authorization"))


if __name__ == "__main__":
    unittest.main()
