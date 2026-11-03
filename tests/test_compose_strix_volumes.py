import os
import re
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestComposeStrixVolumes(unittest.TestCase):
    def _read_file(self, rel_path: str) -> str:
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()

    def test_dockerfile_precreates_strix_scans_for_non_root_user(self):
        content = self._read_file("Dockerfile")
        mkdir_lines = [line for line in content.splitlines() if "mkdir -p" in line]
        self.assertTrue(mkdir_lines, "Dockerfile should contain a mkdir -p line")
        self.assertTrue(
            any("/app/strix_scans" in line for line in mkdir_lines),
            "Dockerfile mkdir -p line must include /app/strix_scans",
        )

    def test_strix_dind_uses_dedicated_strix_scans_dind_volume(self):
        content = self._read_file("docker-compose.strix-dind.yml")
        self.assertIn("strix_scans_dind:/app/strix_scans", content)
        self.assertIsNotNone(
            re.search(r"^\s+strix_scans_dind:\s*$", content, re.MULTILINE),
            "docker-compose.strix-dind.yml must define strix_scans_dind: volume",
        )
        self.assertNotIn("- strix_scans:/app/strix_scans", content)

    def test_strix_socket_keeps_strix_scans_volume(self):
        content = self._read_file("docker-compose.strix.yml")
        self.assertIn("strix_scans:/app/strix_scans", content)

    def test_compose_files_use_portable_volumes_without_hardcoded_host_paths(self):
        for fname in ("docker-compose.yml", "docker-compose.strix.yml", "docker-compose.strix-dind.yml"):
            content = self._read_file(fname)
            self.assertNotIn("/home/uzem", content, f"{fname} must not contain hardcoded /home/uzem path")
            self.assertNotIn("/www/wwwroot", content, f"{fname} must not contain hardcoded /www/wwwroot path")
            self.assertIn("${WSS_PROJECTS_DIR:-~}:/workspace:ro", content, f"{fname} must mount portable workspace")


if __name__ == "__main__":
    unittest.main()
