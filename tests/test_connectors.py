import io
import json
import unittest

import ai_connector as m


class _CapturedResponse(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _install_capture(payload_bytes):
    """ai_connector._urlopen_with_retry'i yakalayan bir sahte ile degistirir; (requests, restore) doner."""
    captured = []
    orig = m._urlopen_with_retry

    def fake(req, timeout=None, retries=None):
        body = req.data.decode("utf-8") if req.data else ""
        captured.append({"url": req.full_url, "headers": dict(req.header_items()), "body": body})
        return _CapturedResponse(payload_bytes)

    m._urlopen_with_retry = fake
    return captured, (lambda: setattr(m, "_urlopen_with_retry", orig))


class AnthropicConnectorTests(unittest.TestCase):
    def test_no_workspace_header_by_default(self):
        """2026-10-31 regresyonu: anthropic-workspace-id basligi VARSAYILAN gonderilmemeli."""
        conn = m.AIProviderFactory.create_connector({"provider": "anthropic", "api_key": "k", "model": "claude-sonnet-5-5"})
        payload = json.dumps({"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 3, "output_tokens": 1}}).encode()
        captured, restore = _install_capture(payload)
        try:
            out = conn.chat("hi", json_mode=True)
        finally:
            restore()
        self.assertEqual(out, "ok")
        hdr_keys = {k.lower() for k in captured[0]["headers"]}
        self.assertNotIn("anthropic-workspace-id", hdr_keys)
        self.assertIn("x-api-key", hdr_keys)
        self.assertEqual(conn.pop_usage(), {"input_tokens": 3, "output_tokens": 1})

    def test_workspace_header_only_when_explicit(self):
        conn = m.AIProviderFactory.create_connector({"provider": "anthropic", "api_key": "k", "workspace_id": "wrkspc_X"})
        captured, restore = _install_capture(json.dumps({"content": [{"type": "text", "text": "ok"}]}).encode())
        try:
            conn.chat("hi")
        finally:
            restore()
        self.assertEqual(captured[0]["headers"].get("Anthropic-workspace-id"), "wrkspc_X")


class AzureConnectorTests(unittest.TestCase):
    def test_url_shape_and_json_mode(self):
        conn = m.AIProviderFactory.create_connector({
            "provider": "azure", "api_key": "k", "endpoint": "https://res.openai.azure.com",
            "deployment": "gpt4o", "api_version": "2024-10-21"})
        payload = json.dumps({"choices": [{"message": {"content": "{}"}}], "usage": {"prompt_tokens": 2, "completion_tokens": 1}}).encode()
        captured, restore = _install_capture(payload)
        try:
            conn.chat("hi", json_mode=True)
        finally:
            restore()
        self.assertIn("/openai/deployments/gpt4o/chat/completions?api-version=2024-10-21", captured[0]["url"])
        self.assertEqual(captured[0]["headers"].get("Api-key"), "k")
        self.assertEqual(json.loads(captured[0]["body"]).get("response_format"), {"type": "json_object"})


class BedrockConnectorTests(unittest.TestCase):
    def test_sigv4_headers_and_anthropic_payload(self):
        conn = m.AIProviderFactory.create_connector({
            "provider": "bedrock", "access_key": "AKIAEXAMPLE", "secret_key": "secret",
            "region": "us-east-1", "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0"})
        payload = json.dumps({"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 4, "output_tokens": 2}}).encode()
        captured, restore = _install_capture(payload)
        try:
            out = conn.chat("hi", system_prompt="sys")
        finally:
            restore()
        self.assertEqual(out, "ok")
        auth = captured[0]["headers"].get("Authorization", "")
        self.assertIn("AWS4-HMAC-SHA256", auth)
        self.assertIn("Credential=AKIAEXAMPLE/", auth)
        self.assertIn("SignedHeaders=content-type;host;x-amz-date", auth)
        self.assertIn("bedrock-runtime.us-east-1.amazonaws.com", captured[0]["url"])
        body = json.loads(captured[0]["body"])
        self.assertEqual(body["anthropic_version"], "bedrock-2023-05-31")
        self.assertEqual(body["system"], "sys")


class TelemetryAndErrorTests(unittest.TestCase):
    def test_http_error_is_captured_not_raised(self):
        conn = m.AIProviderFactory.create_connector({"provider": "anthropic", "api_key": "k"})
        import urllib.error
        orig = m._urlopen_with_retry

        def boom(req, timeout=None, retries=None):
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, io.BytesIO(b'{"error":"x"}'))
        m._urlopen_with_retry = boom
        try:
            out = conn.chat("hi")
        finally:
            m._urlopen_with_retry = orig
        self.assertTrue(out.startswith("Error: Anthropic HTTP 404"))
        tele = conn.get_telemetry()[-1]
        self.assertFalse(tele["ok"])


if __name__ == "__main__":
    unittest.main()
