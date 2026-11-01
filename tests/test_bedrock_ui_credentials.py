import unittest

import ai_connector as m


class BedrockUICredentialTests(unittest.TestCase):
    def test_colon_format(self):
        cfg = m._with_bedrock_credentials({"provider": "bedrock", "api_key": "AKIAEXAMPLE:secretvalue:tok"})
        self.assertEqual((cfg["access_key"], cfg["secret_key"], cfg["session_token"]),
                         ("AKIAEXAMPLE", "secretvalue", "tok"))

    def test_json_format_from_auth_value(self):
        cfg = m._with_bedrock_credentials({"provider": "bedrock", "auth": {
            "type": "service_account", "value": '{"aws_access_key_id": "AKIAX", "aws_secret_access_key": "SK"}'}})
        self.assertEqual((cfg["access_key"], cfg["secret_key"]), ("AKIAX", "SK"))

    def test_explicit_fields_untouched(self):
        cfg = m._with_bedrock_credentials({"access_key": "A", "secret_key": "B", "api_key": "X:Y"})
        self.assertEqual((cfg["access_key"], cfg["secret_key"]), ("A", "B"))

    def test_factory_with_ui_shaped_config(self):
        conn = m.AIProviderFactory.create_connector({
            "provider": "bedrock", "model": "anthropic.claude-3-5-sonnet-20241022-v2:0", "region": "us-west-2",
            "auth": {"type": "service_account", "value": "AKIAX:SKY"}, "api_key": "AKIAX:SKY"})
        inner = conn._inner
        self.assertEqual((inner.access_key, inner.region, inner.model_id),
                         ("AKIAX", "us-west-2", "anthropic.claude-3-5-sonnet-20241022-v2:0"))
        self.assertEqual(len(inner.secret_key), 3)


if __name__ == "__main__":
    unittest.main()
