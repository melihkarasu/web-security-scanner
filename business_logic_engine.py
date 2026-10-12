import urllib.request
import urllib.parse
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# =============================================================
# Faz 6F: İş Mantığı Test Motoru (Business Logic Engine)
# =============================================================

class BusinessLogicEngine:
    """
    Uygulamanın mantıksal akışındaki zafiyetleri (Race Condition, 
    Numerik Manipülasyon, Workflow Bypass) tespit eden motordur.
    """

    def __init__(self, client):
        self.client = client
        # Numerik Manipülasyon için test değerleri (Boundary Values)
        self.numeric_payloads = {
            "negative": ["-1", "-0.01", "-999999"],
            "overflow": ["2147483647", "4294967295", "9223372036854775807"],
            "zero": ["0", "0.00"],
            "large_float": ["1e10", "NaN", "Infinity"]
        }
        # Workflow Bypass için yaygın parametreler
        self.bypass_params = {
            "step": ["final", "done", "success", "payment_complete"],
            "role": ["admin", "superadmin", "root", "moderator"],
            "access": ["full", "authorized", "granted"],
            "is_admin": ["true", "1", "yes"],
            "debug": ["true", "1"]
        }

    def run(self, url):
        findings = []
        
        # 1. Numerik Manipülasyon Testi
        findings += self._test_numeric_manipulation(url)
        
        # 2. İş Akışı Bypass Testi
        findings += self._test_workflow_bypass(url)
        
        # 3. Race Condition Analizi (Sadece belirli kritik uç noktalarda)
        # Gerçek senaryoda crawler'dan gelen 'transfer', 'withdraw' gibi keywordler kullanılır.
        findings += self._test_race_condition(url)

        return findings

    def _test_numeric_manipulation(self, url):
        findings = []
        # Test edilecek yaygın numerik parametre isimleri
        numeric_keywords = ["price", "amount", "qty", "quantity", "discount", "balance", "total"]
        
        for key in numeric_keywords:
            for category, values in self.numeric_payloads.items():
                for val in values:
                    params = {key: val}
                    resp = self.client.get(url, params=params)
                    
                    if resp.get("error"): continue
                    
                    # Basit analiz: Olumsuz değer gönderildiğinde 200 dönmesi ve 
                    # yanıt içeriğinde "başarılı" veya "onaylandı" gibi ifadelerin olması şüphe uyandırır.
                    if resp.get("status") == 200:
                        body = resp.get("body", "").lower()
                        if any(word in body for word in ["success", "başarılı", "complete", "done"]):
                            findings.append({
                                "severity": "YÜKSEK",
                                "test": "Numerik Manipülasyon",
                                "title": f"Potansiyel {category} manipülasyonu ({key}={val})",
                                "url": url,
                                "evidence": f"Parametre {key} için {val} değeri kabul edildi ve başarılı yanıt döndü."
                            })
                            # Aynı kategori için bir tane bulsak yeterli
                            break 
        return findings

    def _test_workflow_bypass(self, url):
        findings = []
        for param, values in self.bypass_params.items():
            for val in values:
                params = {param: val}
                resp = self.client.get(url, params=params)
                
                if resp.get("error"): continue
                
                # 403 veya 401 yerine 200 dönmesi ve içerikte yetki artışı belirtisi
                if resp.get("status") == 200:
                    body = resp.get("body", "").lower()
                    if any(word in body for word in ["admin", "dashboard", "root", "authorized", "panel"]):
                        findings.append({
                            "severity": "KRİTİK",
                            "test": "İş Akışı Bypass",
                            "title": f"Yetki Yükseltme / Bypass ({param}={val})",
                            "url": url,
                            "evidence": f"Sistem {param}={val} parametresiyle yetkili içerik döndürdü."
                        })
                        break
        return findings

    def _test_race_condition(self, url):
        findings = []
        # Race condition genellikle POST isteklerinde (örn: bakiye transferi) olur.
        # Ancak GET üzerinden simülasyon yapmak için '/race' veya '/transfer' içeren URL'ler aranır.
        if "race" not in url.lower() and "transfer" not in url.lower():
            return findings

        # Aynı isteği çok kısa aralıkla paralel gönder
        results = []
        def send_req():
            # Rate limit'e takılmamak için client üzerinden gönderiyoruz
            res = self.client.get(url)
            results.append(res)

        with ThreadPoolExecutor(max_workers=5) as executor:
            for _ in range(5):
                executor.submit(send_req)

        # Yanıtlar arasındaki tutarsızlıkları kontrol et
        # Örn: 5 isteğin hepsinin 'başarılı' dönmesi ama toplamda sadece 1 kez işlem yapılması gerekmesi
        success_count = sum(1 for r in results if r.get("status") == 200 and "success" in r.get("body", "").lower())
        
        if success_count > 1:
            findings.append({
                "severity": "YÜKSEK",
                "test": "Race Condition",
                "title": "Potansiyel Yarış Durumu Zafiyeti",
                "url": url,
                "evidence": f"{success_count} adet paralel istek aynı anda başarıyla tamamlandı."
            })
            
        return findings

def run_business_logic_scan(url, client):
    engine = BusinessLogicEngine(client)
    return engine.run(url)
