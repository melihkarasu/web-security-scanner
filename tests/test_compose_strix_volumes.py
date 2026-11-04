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

    def test_dockerfile_defaults_include_strix_and_chromium(self):
        content = self._read_file("Dockerfile")
        self.assertIn("ARG INSTALL_CHROMIUM=1", content)
        self.assertIn("ARG INSTALL_STRIX=1", content)
        self.assertIn("chromium-headless-shell", content)
        self.assertIn("strix-agent", content)
        self.assertIn("WSS_BROWSER_NO_SANDBOX=1", content)

    def test_install_sh_enables_browser_and_strix_by_default_for_full(self):
        content = self._read_file("install.sh")
        self.assertIn('if [ "$EDITION" = "full" ]; then', content)
        self.assertIn('WITH_BROWSER="1"', content)
        self.assertIn('WITH_STRIX="1"', content)
        self.assertIn("INSTALL_CHROMIUM=", content)
        self.assertIn("INSTALL_STRIX=", content)

    def test_header_has_no_report_export_buttons_before_scan(self):
        html = self._read_file("index.html")
        header_match = re.search(r"<header\b[^>]*>(.*?)</header>", html, re.S)
        self.assertIsNotNone(header_match)
        header_html = header_match.group(1)
        for fn in ("exportMarkdownReport", "exportJsonReport", "exportHtmlReport"):
            self.assertNotIn(fn, header_html, f"{fn} should not be in <header>")
            self.assertIn(fn, html, f"{fn} should remain in #results-export-toolbar")

    def test_strix_dind_uses_dedicated_strix_scans_dind_volume(self):
        content = self._read_file("docker-compose.strix-dind.yml")
        self.assertIn("strix_scans_dind:/app/strix_scans", content)
        self.assertIsNotNone(
            re.search(r"^\s+strix_scans_dind:\s*$", content, re.MULTILINE),
            "docker-compose.strix-dind.yml volumes section must declare strix_scans_dind",
        )


if __name__ == "__main__":
    unittest.main()
