"""Testler icin rol bazli senaryolu sahte LLM (PentAGI'nin mock LLM test katmaninin uyarlamasi).

AIConnector tabanindan turer ve yalnizca _chat_impl'i uygular; boylece gercek base-class
chat()/telemetri yolu ve RedactingConnector sarmalayicisi da test edilmis olur. Aldigi
(maskelenmis) prompt'lari kaydeder.
"""
import json
import threading

from ai_connector import AIConnector


class MockLLM(AIConnector):
    def __init__(self, plan_factory):
        self.prompts = []
        self.model = "mock"
        self._plan_factory = plan_factory
        self._strategist_calls = 0
        self._lock = threading.Lock()

    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        text = (system_prompt or "") + "\n" + (prompt or "")
        with self._lock:
            self.prompts.append(text)
        if "You are The Analyst" in text:
            if "alert(1)" in text and "Results for" in text:
                return json.dumps({"verdict": "VULNERABLE", "severity": "high", "cwe": "CWE-79",
                                   "evidence_quote": "Results for: <script>alert(1)</script>"})
            if "SQL syntax" in text:
                return json.dumps({"verdict": "VULNERABLE", "severity": "high", "cwe": "CWE-89",
                                   "evidence_quote": "You have an error in your SQL syntax"})
            return json.dumps({"verdict": "NOT_VULNERABLE", "severity": "low", "cwe": "-", "evidence_quote": ""})
        if "You are The Strategist" in text:
            with self._lock:
                self._strategist_calls += 1
                first = self._strategist_calls == 1
            return json.dumps(self._plan_factory() if first else [])
        if "You are The Reporter" in text:
            return "### Yonetici Ozeti\nSahte LLM raporu."
        return "Scout degerlendirmesi: /search?q ve /item?id parametreleri oncelikli."
