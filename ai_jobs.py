#!/usr/bin/env python3
"""
ai_jobs.py — Arka planda çalışan, canlı izlenebilen AI Red Team işleri (Faz 2).

PentAGI'deki akış kontrolünün (durdur / ek talimat / "ask" bariyeri) bu araca uyarlanmış,
yalnızca Python standart kütüphanesi kullanan hâli:
  - İş ayrı bir iş parçacığında çalışır; arayüz /api/ai-status ile olayları artımlı çeker.
  - İptal bir sonraki adımda etkili olur (o anki LLM çağrısı / HTTP isteği tamamlanır).
  - Kullanıcı notları Stratejist'e bir sonraki planlamada iletilir.
  - Soru (ask): AI riskli bir uca dokunmadan önce sorar; cevap gelmezse güvenli varsayılan
    (testi atlamak) uygulanır.
Durum yalnızca bellekte tutulur; sunucu yeniden başlarsa işler kaybolur.
"""

import threading
import time
import uuid

from redaction import redact_text

MAX_RUNNING_JOBS = 2
MAX_KEPT_JOBS = 20
JOB_TTL_SECONDS = 3600
MAX_EVENTS = 2000
MAX_NOTES = 5
MAX_NOTE_CHARS = 500
MAX_QUESTIONS = 3
DEFAULT_ASK_TIMEOUT = 120
ACTIVE_STATUSES = ("queued", "running", "waiting_input")


class JobLimitError(Exception):
    """Aynı anda çalışabilecek AI işi sınırı aşıldı."""


class AIJob:
    def __init__(self, target):
        self.id = uuid.uuid4().hex
        self.target = target
        self.status = "queued"
        self.created_at = time.time()
        self.finished_at = None
        self.result = None
        self.error = None
        self.cancel_event = threading.Event()
        self.questions_asked = 0
        self.ask_timeout = DEFAULT_ASK_TIMEOUT
        self.notes_log = []
        self._lock = threading.Lock()
        self._events = []
        self._next_seq = 0
        self._notes_pending = []
        self._question = None
        self._answer_event = threading.Event()
        self._answer_value = None

    # ---------------- olay akışı ----------------
    def push_event(self, entry):
        with self._lock:
            ev = dict(entry)
            ev["seq"] = self._next_seq
            self._next_seq += 1
            self._events.append(ev)
            if len(self._events) > MAX_EVENTS:
                self._events = self._events[-MAX_EVENTS:]

    def emit(self, agent, message):
        self.push_event({"agent": agent, "message": redact_text(str(message))[:500],
                         "ts": int(time.time() * 1000)})

    # ---------------- kontrol arayüzü (orkestratör kullanır) ----------------
    def is_cancelled(self):
        return self.cancel_event.is_set()

    def cancel(self):
        if self.status not in ACTIVE_STATUSES:
            return False
        if not self.cancel_event.is_set():
            self.cancel_event.set()
            self.emit("system", "⏹️ İptal istendi; tarama o anki adım bitince duracak.")
        self._answer_event.set()  # bekleyen soruyu serbest bırak → güvenli varsayılan
        return True

    def add_note(self, text):
        text = str(text or "").strip()[:MAX_NOTE_CHARS]
        if not text:
            return False, "Not boş olamaz."
        if self.status not in ACTIVE_STATUSES:
            return False, "Tarama çalışmıyor."
        with self._lock:
            if len(self.notes_log) >= MAX_NOTES:
                return False, "En fazla %d not eklenebilir." % MAX_NOTES
            self.notes_log.append(text)
            self._notes_pending.append(text)
        self.emit("user", "📝 Not alındı (bir sonraki planlamada dikkate alınacak): " + text)
        return True, ""

    def pop_notes(self):
        with self._lock:
            notes, self._notes_pending = self._notes_pending, []
        return notes

    def ask(self, text, options, default, timeout=None, context=None):
        """Kullanıcıya sorar ve cevabı bekler. Cevap yoksa / iptalde / limitte default döner."""
        options = [str(o) for o in (options or [])][:4]
        if default not in options:
            default = options[-1] if options else ""
        if self.is_cancelled():
            return default
        if self.questions_asked >= MAX_QUESTIONS:
            self.emit("system", "Soru limiti (%d) doldu; güvenli seçenek uygulandı: %s" % (MAX_QUESTIONS, default))
            return default
        wait_for = max(1, min(600, int(timeout or self.ask_timeout or DEFAULT_ASK_TIMEOUT)))
        qid = uuid.uuid4().hex[:12]
        with self._lock:
            self.questions_asked += 1
            self._answer_event.clear()
            self._answer_value = None
            self._question = {
                "id": qid, "text": redact_text(str(text))[:600], "options": options,
                "default": default, "context": redact_text(str(context or ""))[:400],
                "asked_at": int(time.time() * 1000), "expires_at": int((time.time() + wait_for) * 1000),
            }
            self.status = "waiting_input"
        self.emit("system", "❓ Onay bekleniyor: " + str(text)[:300])
        deadline = time.time() + wait_for
        while time.time() < deadline and not self._answer_event.is_set():
            self._answer_event.wait(0.5)
        with self._lock:
            answer = self._answer_value
            self._question = None
            if self.status == "waiting_input":
                self.status = "running"
        if answer is None:
            reason = "iptal edildi" if self.is_cancelled() else "cevap gelmedi (%d sn)" % wait_for
            self.emit("system", "⏱️ %s; güvenli seçenek uygulandı: %s" % (reason[0].upper() + reason[1:], default))
            return default
        self.emit("user", "✅ Cevap: " + answer)
        return answer

    def answer(self, question_id, value):
        with self._lock:
            q = self._question
            if not q or q["id"] != str(question_id or ""):
                return False, "Bu kimlikte bekleyen bir soru yok."
            if value not in q["options"]:
                return False, "Geçersiz seçenek."
            self._answer_value = value
        self._answer_event.set()
        return True, ""

    # ---------------- görünüm ----------------
    def view(self, since=0):
        try:
            since = max(0, int(since or 0))
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            events = [e for e in self._events if e["seq"] >= since]
            question = dict(self._question) if self._question else None
            next_seq = self._next_seq
            status = self.status
            notes = list(self.notes_log)
        out = {
            "success": True, "job_id": self.id, "status": status, "target": self.target,
            "events": events, "next_seq": next_seq, "pending_question": question, "notes": notes,
            "elapsed_ms": int(((self.finished_at or time.time()) - self.created_at) * 1000),
        }
        if status not in ACTIVE_STATUSES:
            out["result"] = self.result
            out["error"] = self.error
        return out


class AIJobManager:
    def __init__(self, max_running=MAX_RUNNING_JOBS):
        self.max_running = max_running
        self._jobs = {}
        self._lock = threading.Lock()

    def _prune_locked(self):
        now = time.time()
        for jid in [j.id for j in self._jobs.values() if j.finished_at and now - j.finished_at > JOB_TTL_SECONDS]:
            self._jobs.pop(jid, None)
        finished = sorted((j for j in self._jobs.values() if j.finished_at), key=lambda j: j.finished_at)
        while len(self._jobs) > MAX_KEPT_JOBS and finished:
            self._jobs.pop(finished.pop(0).id, None)

    def start(self, target, runner, ask_timeout=None):
        with self._lock:
            self._prune_locked()
            active = sum(1 for j in self._jobs.values() if j.status in ACTIVE_STATUSES)
            if active >= self.max_running:
                raise JobLimitError("Aynı anda en fazla %d AI taraması çalışabilir." % self.max_running)
            job = AIJob(target)
            if ask_timeout:
                try:
                    job.ask_timeout = max(1, min(600, int(ask_timeout)))
                except (TypeError, ValueError):
                    pass
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, runner), name="ai-job-" + job.id[:8], daemon=True).start()
        return job

    def _run(self, job, runner):
        job.status = "running"
        try:
            result = runner(job)
            job.result = result
            if job.is_cancelled():
                job.status = "cancelled"
            elif isinstance(result, dict) and result.get("success"):
                job.status = "done"
            else:
                res = result if isinstance(result, dict) else {}
                job.error = res.get("message") or res.get("error") or "AI taraması başarısız."
                job.status = "error"
        except Exception as e:
            job.error = "AI Scan Error: %s" % str(e)[:300]
            job.emit("error", job.error)
            job.status = "error"
        finally:
            job.finished_at = time.time()

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(str(job_id or ""))
