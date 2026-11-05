import io
import os
import tarfile
import tempfile
import unittest
from unittest import mock

import updater


class UpdaterTests(unittest.TestCase):
    def test_git_blob_sha1_matches_git_standard(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"hello world\n")
            p = f.name
        try:
            # git hash-object for "hello world\n" is 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
            self.assertEqual(updater.git_blob_sha1(p), "3b18e512dba79e4c8300dd08aeb37f8e728b8dad")
        finally:
            os.unlink(p)

    def test_check_for_updates_detects_up_to_date_and_changed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for rel in updater.TRACKED_CORE_FILES:
                full = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(full) or tmp, exist_ok=True)
                with open(full, "wb") as f:
                    f.write(("content-" + rel).encode("utf-8"))

            tree_items = [
                {"path": rel, "type": "blob", "sha": updater.git_blob_sha1(os.path.join(tmp, rel))}
                for rel in updater.TRACKED_CORE_FILES
            ]

            def fake_get_json(url, timeout=10):
                if "/commits/" in url:
                    return {
                        "sha": "abcdef1234567890abcdef1234567890abcdef12",
                        "commit": {
                            "message": "feat(test): latest release\n\ndetails",
                            "committer": {"date": "2026-11-05T12:00:00Z"},
                            "tree": {"sha": "tree123"},
                        },
                    }
                return {"tree": tree_items}

            with mock.patch("updater._github_get_json", side_effect=fake_get_json):
                res1 = updater.check_for_updates(tmp, force=True)
                self.assertTrue(res1["ok"])
                self.assertFalse(res1["update_available"])
                self.assertTrue(res1["up_to_date"])
                self.assertEqual(res1["current_commit"], "abcdef1")

                # Modify one tracked file locally -> update_available should become True
                with open(os.path.join(tmp, "server.py"), "wb") as f:
                    f.write(b"old-server-content")
                res2 = updater.check_for_updates(tmp, force=True)
                self.assertTrue(res2["update_available"])
                self.assertIn("server.py", res2["changed_files"])

    def test_apply_update_extracts_and_persists_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = os.path.join(tmp, "app")
            data_dir = os.path.join(tmp, "data")
            os.makedirs(app_dir, exist_ok=True)
            os.makedirs(data_dir, exist_ok=True)
            with open(os.path.join(app_dir, "server.py"), "wb") as f:
                f.write(b"v1")

            # Build an in-memory tar.gz archive mimicking GitHub codeload
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                payload = b"v2-updated"
                ti = tarfile.TarInfo("web-security-scanner-main/server.py")
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
                # Protected .env must never be overwritten
                env_bytes = b"SECRET=overwrite"
                ti_env = tarfile.TarInfo("web-security-scanner-main/.env")
                ti_env.size = len(env_bytes)
                tf.addfile(ti_env, io.BytesIO(env_bytes))
            tar_bytes = buf.getvalue()

            with open(os.path.join(app_dir, ".env"), "wb") as f:
                f.write(b"SECRET=keep")

            class FakeResp:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def read(self): return tar_bytes

            with mock.patch("updater.check_for_updates", return_value={
                "ok": True,
                "latest_commit_full": "999888777666555444333222111000aaabbbcccd",
                "latest_message": "feat: new update",
            }), mock.patch("updater.urllib.request.urlopen", return_value=FakeResp()):
                res = updater.apply_update(app_dir, data_dir=data_dir)
                self.assertTrue(res["ok"])
                self.assertIn("server.py", res["updated_files"])
                self.assertEqual(open(os.path.join(app_dir, "server.py"), "rb").read(), b"v2-updated")
                self.assertEqual(open(os.path.join(app_dir, ".env"), "rb").read(), b"SECRET=keep")

                # Simulate container restart (overwrite server.py back to v1 and restore from data_dir)
                with open(os.path.join(app_dir, "server.py"), "wb") as f:
                    f.write(b"v1")
                restored = updater.restore_persisted_update(app_dir, data_dir=data_dir)
                self.assertEqual(restored, 1)
                self.assertEqual(open(os.path.join(app_dir, "server.py"), "rb").read(), b"v2-updated")


if __name__ == "__main__":
    unittest.main()
