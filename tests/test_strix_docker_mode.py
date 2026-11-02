"""Faz 5: Strix Docker modu tespiti (host soketi / izole TLS dind / TLS'siz uzak daemon)."""
import os
import unittest
from unittest import mock

import strix_engine as se


class DockerModeTests(unittest.TestCase):
    def mode(self, env, sock=False, container=False):
        def fake_exists(path):
            if path == "/var/run/docker.sock":
                return sock
            if path == "/.dockerenv":
                return container
            return False
        with mock.patch.dict(os.environ, {}, clear=False):
            for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY"):
                os.environ.pop(key, None)
            os.environ.update(env)
            with mock.patch("strix_engine.os.path.exists", side_effect=fake_exists):
                return se.docker_mode()

    def test_dind_tls_is_secure(self):
        m = self.mode({"DOCKER_HOST": "tcp://127.0.0.1:2376", "DOCKER_TLS_VERIFY": "1"}, sock=True, container=True)
        self.assertEqual((m["mode"], m["secure"]), ("dind-tls", True))

    def test_tcp_without_tls_is_flagged(self):
        m = self.mode({"DOCKER_HOST": "tcp://10.0.0.5:2375"})
        self.assertEqual((m["mode"], m["secure"]), ("remote-tcp-insecure", False))
        self.assertIn("DOCKER_TLS_VERIFY", m["note"])

    def test_socket_mounted_in_container_warns_and_recommends_dind(self):
        m = self.mode({}, sock=True, container=True)
        self.assertEqual((m["mode"], m["secure"]), ("host-socket", False))
        self.assertIn("docker-compose.strix-dind.yml", m["note"])
        self.assertIn(":ro", m["note"])

    def test_native_socket_is_plain_local_daemon(self):
        m = self.mode({}, sock=True, container=False)
        self.assertEqual(m["mode"], "host-socket")
        self.assertNotIn("ele geçiren", m["note"])

    def test_no_docker(self):
        self.assertEqual(self.mode({})["mode"], "none")

    def test_capabilities_always_report_docker_mode(self):
        caps = se.strix_capabilities()
        self.assertIn("docker_mode", caps)
        self.assertIn("mode", caps["docker_mode"])


if __name__ == "__main__":
    unittest.main()
