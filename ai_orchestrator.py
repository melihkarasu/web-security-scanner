import json
import time
from typing import List, Dict, Any, Optional
from ai_connector import AIProviderFactory

# =============================================================
# Faz 6G: AI Ajan Orkestratörü (AI Agent Orchestrator)
# =============================================================
# Bu modül, güvenlik taramasını dinamik hale getiren üçlü ajan
# ekibini (Scout, Strategist, Analyst) yönetir. Maliyet odaklı 
# tasarım ile gereksiz API çağrılarını engeller.
# =============================================================

class AIAgent:
    """Genel ajan yapısı."""
    def __init__(self, name: str, role_prompt: str, connector):
        self.name = name
        self.role_prompt = role_prompt
        self.connector = connector

    def think(self, context: str, user_input: str = "") -> str:
        full_prompt = f"{self.role_prompt}\n\nCONTEXT:\n{context}\n\nINPUT: {user_input}"
        return self.connector.chat(full_prompt)

class AIOrchestrator:
    """
    Ajanlar arası döngüyü yöneten ve maliyet kontrolü yapan ana orkestratör.
    """
    def __init__(self, provider_config: dict, max_loops: int = 5):
        self.connector = AIProviderFactory.create_connector(provider_config)
        self.max_loops = max_loops
        
        # Ajan Personaları (Token tasarrufu için optimize edilmiş promptlar)
        self.scout = AIAgent(
            "The Scout", 
            "You are a Security Scout. Analyze the attack surface (site map, JS files, headers). "
            "Identify high-risk parameters and hidden endpoints. Be concise.", 
            self.connector
        )
        self.strategist = AIAgent(
            "The Strategist", 
            "You are a Red Team Strategist. Based on Scout's findings, create specific attack hypotheses. "
            "Provide payloads and targets in JSON format: [{'url': '...', 'param': '...', 'payload': '...', 'reason': '...'}]", 
            self.connector
        )
        self.analyst = AIAgent(
            "The Analyst", 
            "You are a Vulnerability Analyst. Examine HTTP responses for anomalies, leaks, or reflections. "
            "Determine if a finding is a True Positive or False Positive. Be strict.", 
            self.connector
        )

    def _compress_context(self, history: List[Dict]) -> str:
        """Maliyet kontrolü: Geçmişi özetleyerek token tüketimini azaltır."""
        if not history: return "No previous data."
        summary = []
        for entry in history[-3:]: # Sadece son 3 etkileşimi tut
            summary.append(f"Step {entry['step']}: {entry['result'][:200]}...")
        return "\n".join(summary)

    def orchestrate_scan(self, target_url: str, initial_data: Dict[str, Any], active_scanner_callback):
        """
        Yapay Zeka Destekli Dinamik Tarama Döngüsü.
        active_scanner_callback: (url, param, payload) -> response formatında bir fonksiyon.
        """
        loop_count = 0
        scan_history = []
        verified_findings = []
        current_context = f"Target: {target_url}\nInitial Data: {json.dumps(initial_data)}"

        print(f"[*] AI Orchestration started for {target_url} (Max loops: {self.max_loops})")

        while loop_count < self.max_loops:
            loop_count += 1
            print(f"[*] AI Loop {loop_count}/{self.max_loops} starting...")

            # 1. KEŞİF (The Scout)
            scout_report = self.scout.think(current_context)
            if "Error" in scout_report: break # Circuit Breaker
            print(f"[+] Scout report received.")

            # 2. STRATEJİ (The Strategist)
            strategy_input = f"Scout Report: {scout_report}\nHistory: {self._compress_context(scan_history)}"
            plan_raw = self.strategist.think(strategy_input)
            if "Error" in plan_raw: break # Circuit Breaker
            
            try:
                # JSON temizleme (LLM bazen markdown blokları ekler)
                json_start = plan_raw.find('[')
                json_end = plan_raw.rfind(']') + 1
                plan = json.loads(plan_raw[json_start:json_end])
            except Exception as e:
                print(f"[!] Strategy parsing error: {e}")
                break

            if not plan:
                print("[*] Strategist decided no more tests are needed.")
                break

            # 3. AKTİF TEST (Sistem tarafından yürütülür)
            loop_results = []
            for task in plan:
                print(f"[*] Testing {task.get('param')} with AI payload...")
                # Aktif tarama motoruna testi yaptır
                response = active_scanner_callback(
                    task.get('url', target_url), 
                    task.get('param'), 
                    task.get('payload')
                )
                loop_results.append({"task": task, "response": response})

            # 4. ANALİZ (The Analyst)
            for res in loop_results:
                analysis_input = f"Task: {json.dumps(res['task'])}\nResponse: {json.dumps(res['response'])}"
                verdict = self.analyst.think(analysis_input)
                
                if "True Positive" in verdict or "VULNERABLE" in verdict.upper():
                    print(f"[!!!] AI Verified Finding: {res['task'].get('reason')}")
                    verified_findings.append({
                        "finding": res['task'],
                        "verdict": verdict
                    })

            # Döngü geçmişini güncelle
            scan_history.append({
                "step": loop_count,
                "result": f"Tested {len(plan)} hypotheses, found {len(verified_findings)} issues."
            })
            current_context = f"Current Findings: {json.dumps(verified_findings)}\nLast Loop: {scout_report}"

        print(f"[*] AI Orchestration finished. Total loops: {loop_count}")
        return {
            "verified_findings": verified_findings,
            "loops": loop_count,
            "history": scan_history
        }
