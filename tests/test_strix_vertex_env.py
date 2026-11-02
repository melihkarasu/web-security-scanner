"""Faz 5+: Strix build_strix_env Vertex kimlik + konum düzeltmesi (regresyon koruması)."""
import json
import os
import tempfile
import unittest

import strix_engine as se


def _sa(project="proj-xyz"):
    return {"type": "service_account", "project_id": project,
            "client_email": "svc@%s.iam.gserviceaccount.com" % project,
            "private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}


class StrixVertexEnvTests(unittest.TestCase):
    def test_service_account_as_file_path(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(_sa(), f)
            env = se.build_strix_env({"provider": "vertex", "model": "gemini-3.8-flash",
                                      "region": "global", "auth": {"type": "service_account", "value": path}})
            self.assertEqual(env["STRIX_LLM"], "vertex_ai/gemini-3.8-flash")
            gac = env["GOOGLE_APPLICATION_CREDENTIALS"]
            self.assertTrue(os.path.isfile(gac))
            # credential file must be valid SA JSON (the bug wrote the *path string* as file content)
            self.assertEqual(json.load(open(gac)).get("project_id"), "proj-xyz")
            self.assertEqual(env["VERTEXAI_PROJECT"], "proj-xyz")
            self.assertEqual(env["VERTEXAI_LOCATION"], "global")
        finally:
            os.remove(path)

    def test_service_account_as_raw_json(self):
        env = se.build_strix_env({"provider": "vertex", "model": "gemini-3.8-flash",
                                  "project_id": "override-proj",
                                  "auth": {"type": "service_account", "value": json.dumps(_sa("inner-proj"))}})
        gac = env["GOOGLE_APPLICATION_CREDENTIALS"]
        self.assertEqual(json.load(open(gac)).get("client_email"), "svc@inner-proj.iam.gserviceaccount.com")
        # explicit project_id overrides the SA's project
        self.assertEqual(env["VERTEXAI_PROJECT"], "override-proj")
        os.remove(gac)

    def test_region_defaults_to_global(self):
        env = se.build_strix_env({"provider": "vertex", "model": "gemini-3.8-flash", "project_id": "p",
                                  "auth": {"type": "service_account", "value": json.dumps(_sa())}})
        self.assertEqual(env["VERTEXAI_LOCATION"], "global")
        os.remove(env["GOOGLE_APPLICATION_CREDENTIALS"])

    def test_preflight_timeout_and_retries_present(self):
        env = se.build_strix_env({"provider": "openai", "model": "gpt-4o", "api_key": "x"})
        self.assertIn("LLM_PREFLIGHT_TIMEOUT", env)
        self.assertEqual(env["LITELLM_NUM_RETRIES"], "4")
        self.assertTrue(int(env["LLM_PREFLIGHT_TIMEOUT"]) >= 120)

    def test_preflight_timeout_overridable(self):
        env = se.build_strix_env({"provider": "openai", "model": "gpt-4o", "api_key": "x",
                                  "llm_preflight_timeout": "90"})
        self.assertEqual(env["LLM_PREFLIGHT_TIMEOUT"], "90")


if __name__ == "__main__":
    unittest.main()
