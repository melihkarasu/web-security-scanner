import threading
import time
import unittest

import ai_jobs


class AIJobTests(unittest.TestCase):
    def setUp(self):
        self.mgr = ai_jobs.AIJobManager(max_running=2)

    def wait_done(self, job, timeout=10):
        t0 = time.time()
        while job.status in ai_jobs.ACTIVE_STATUSES and time.time() - t0 < timeout:
            time.sleep(0.05)
        return job.status

    def wait_question(self, job, timeout=5):
        t0 = time.time()
        while time.time() - t0 < timeout:
            q = job.view()["pending_question"]
            if q:
                return q
            time.sleep(0.05)
        return None

    def test_events_stream_incrementally_and_result_only_when_finished(self):
        gate = threading.Event()

        def runner(job):
            job.emit("system", "adım 1")
            gate.wait(5)
            job.emit("system", "adım 2")
            return {"success": True, "x": 1}
        job = self.mgr.start("http://t", runner)
        time.sleep(0.2)
        v1 = job.view(0)
        self.assertEqual([e["message"] for e in v1["events"]], ["adım 1"])
        self.assertNotIn("result", v1)
        gate.set()
        self.assertEqual(self.wait_done(job), "done")
        v2 = job.view(v1["next_seq"])
        self.assertEqual([e["message"] for e in v2["events"]], ["adım 2"])
        self.assertEqual(v2["result"]["x"], 1)

    def test_cancel_marks_cancelled_and_is_idempotent(self):
        def runner(job):
            while not job.is_cancelled():
                time.sleep(0.05)
            return {"success": False, "cancelled": True}
        job = self.mgr.start("t", runner)
        time.sleep(0.1)
        self.assertTrue(job.cancel())
        self.assertEqual(self.wait_done(job), "cancelled")
        self.assertFalse(job.cancel())

    def test_notes_delivered_once_and_rejected_after_finish(self):
        got = []

        def runner(job):
            t0 = time.time()
            while time.time() - t0 < 3 and not got:
                got.extend(job.pop_notes())
                time.sleep(0.05)
            return {"success": True}
        job = self.mgr.start("t", runner)
        ok, _ = job.add_note("Sadece /search parametresine odaklan")
        self.assertTrue(ok)
        self.wait_done(job)
        self.assertEqual(got, ["Sadece /search parametresine odaklan"])
        self.assertFalse(job.add_note("geç kaldım")[0])

    def test_ask_answer_validation_and_timeout_default(self):
        answers = []

        def runner(job):
            answers.append(job.ask("Test edilsin mi?", ["Evet", "Hayır"], "Hayır", timeout=10))
            answers.append(job.ask("İkinci?", ["Evet", "Hayır"], "Hayır", timeout=1))
            return {"success": True}
        job = self.mgr.start("t", runner)
        q = self.wait_question(job)
        self.assertIsNotNone(q)
        self.assertEqual(job.view()["status"], "waiting_input")
        self.assertFalse(job.answer("yanlis-id", "Evet")[0])
        self.assertFalse(job.answer(q["id"], "Belki")[0])
        self.assertTrue(job.answer(q["id"], "Evet")[0])
        self.assertEqual(self.wait_done(job), "done")
        self.assertEqual(answers, ["Evet", "Hayır"])

    def test_cancel_releases_pending_question_with_safe_default(self):
        res = []

        def runner(job):
            res.append(job.ask("?", ["Evet", "Hayır"], "Hayır", timeout=30))
            return {"success": False, "cancelled": True}
        job = self.mgr.start("t", runner)
        self.assertIsNotNone(self.wait_question(job))
        job.cancel()
        self.assertEqual(self.wait_done(job), "cancelled")
        self.assertEqual(res, ["Hayır"])

    def test_question_limit_applies_default(self):
        res = []

        def runner(job):
            for _ in range(ai_jobs.MAX_QUESTIONS + 1):
                res.append(job.ask("?", ["Evet", "Hayır"], "Hayır", timeout=1))
            return {"success": True}
        job = self.mgr.start("t", runner)
        self.wait_done(job, 15)
        self.assertEqual(res, ["Hayır"] * (ai_jobs.MAX_QUESTIONS + 1))
        self.assertEqual(job.questions_asked, ai_jobs.MAX_QUESTIONS)

    def test_running_job_limit(self):
        gate = threading.Event()

        def runner(job):
            gate.wait(5)
            return {"success": True}
        try:
            self.mgr.start("a", runner)
            self.mgr.start("b", runner)
            with self.assertRaises(ai_jobs.JobLimitError):
                self.mgr.start("c", runner)
        finally:
            gate.set()

    def test_runner_exception_sets_error(self):
        def runner(job):
            raise RuntimeError("boom")
        job = self.mgr.start("t", runner)
        self.assertEqual(self.wait_done(job), "error")
        self.assertIn("boom", job.view()["error"])

    def test_events_are_redacted(self):
        def runner(job):
            job.emit("system", "Set-Cookie: session=SUPERSECRET123; HttpOnly")
            return {"success": True}
        job = self.mgr.start("t", runner)
        self.wait_done(job)
        self.assertNotIn("SUPERSECRET123", job.view()["events"][0]["message"])


if __name__ == "__main__":
    unittest.main()
