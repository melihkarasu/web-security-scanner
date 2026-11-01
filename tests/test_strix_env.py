import unittest

import strix_engine as se


def _k(*parts):
    """Test anahtarlarını çalışma zamanında üretir (kaynakta sır benzeri literal bulunmasın)."""
    return "-".join(parts)


class StrixProviderMappingTests(unittest.TestCase):
    def test_anthropic(self):
        key = _k("unit", "test", "anthropic")
        env = se.build_strix_env({"provider": "anthropic", "model": "claude-sonnet-5-5", "api_key": key})
        self.assertEqual(env["STRIX_LLM"], "anthropic/claude-sonnet-5-5")
        self.assertEqual(env["ANTHROPIC_API_KEY"], key)
        self.assertNotEqual(env.get("OPENAI_API_KEY"), key)

    def test_azure(self):
        key = _k("unit", "test", "azure")
        env = se.build_strix_env({"provider": "azure", "model": "gpt4o-deploy", "api_key": key,
                                  "base_url": "https://res.openai.azure.com"})
        self.assertEqual(env["STRIX_LLM"], "azure/gpt4o-deploy")
        self.assertEqual(env["AZURE_API_KEY"], key)
        self.assertEqual(env["AZURE_API_BASE"], "https://res.openai.azure.com")
        self.assertEqual(env["AZURE_API_VERSION"], "2024-10-21")

    def test_azure_requires_endpoint(self):
        with self.assertRaises(ValueError):
            se.build_strix_env({"provider": "azure", "model": "d", "api_key": _k("unit", "azure")})

    def test_bedrock(self):
        creds = ":".join(("AKIAX", "SKY", "TOK"))
        env = se.build_strix_env({"provider": "bedrock", "model": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                                  "region": "eu-central-1", "api_key": creds,
                                  "auth": {"type": "service_account", "value": creds}})
        self.assertEqual(env["STRIX_LLM"], "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0")
        self.assertEqual((env["AWS_ACCESS_KEY_ID"], env["AWS_SESSION_TOKEN"], env["AWS_REGION_NAME"]),
                         ("AKIAX", "TOK", "eu-central-1"))
        self.assertEqual(env["AWS_SECRET_ACCESS_KEY"], "SKY")

    def test_bedrock_requires_credentials(self):
        with self.assertRaises(ValueError):
            se.build_strix_env({"provider": "bedrock", "model": "m", "api_key": "only-one-part"})

    def test_existing_openai_mapping_unchanged(self):
        key = _k("unit", "test", "openai")
        env = se.build_strix_env({"provider": "openai", "model": "gpt-4o", "api_key": key,
                                  "base_url": "https://api.openai.com/v1"})
        self.assertEqual(env["STRIX_LLM"], "openai/gpt-4o")
        self.assertEqual(env["OPENAI_API_KEY"], key)
        self.assertEqual(env["LLM_API_BASE"], "https://api.openai.com/v1")


if __name__ == "__main__":
    unittest.main()
