"""Testler için rol bazlı senaryolu sahte LLM (PentAGI'nin mock LLM test katmanının uyarlaması).

Gerçek sağlayıcı yerine AIProviderFactory._create_raw_connector ile enjekte edilir; böylece
RedactingConnector sarmalayıcısı da test edilmiş olur. Aldığı (maskelenmiş) prompt'ları kaydeder.
"""
import json
import threading


class MockLLM:
    def __init__(self, plan_factory):
        self.prompts = []
        self._plan_factory = plan_factory
        self._strategist_calls = 0
        self._lock = threading.Lock()

    def chat(self, prompt, system_prompt=""):
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
            return "### Yönetici Özeti\nSahte LLM raporu."
        return "Scout değerlendirmesi: /search?q ve /item?id parametreleri öncelikli."
