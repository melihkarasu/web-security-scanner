import json
import os
import base64
import urllib.request
import urllib.parse
import urllib.error
from abc import ABC, abstractmethod

# =============================================================
# Faz 6G: AI Bağlantı Katmanı (AI Connector Layer)
# =============================================================
# Bu modül, farklı LLM sağlayıcılarını (Vertex AI, OpenRouter, Ollama)
# tek bir standart arayüz altına toplar. Güvenlik önceliği ile 
# Service Account ve API Key yönetimini bellek üzerinde yapar.
# =============================================================

class AIConnector(ABC):
    """Tüm AI sağlayıcıları için temel soyutlama sınıfı."""
    @abstractmethod
    def chat(self, prompt: str, system_prompt: str = "") -> str:
        pass

class VertexAIConnector(AIConnector):
    """
    Google Vertex AI entegrasyonu. 
    Hem API Key hem de Service Account (JSON dosya/içerik) destekler.
    """
    def __init__(self, project_id: str, region: str = "us-central1", 
                 model_name: str = "gemini-1.5-pro", 
                 auth_config: dict = None):
        """
        auth_config: {
            "type": "api_key" | "service_account",
            "value": "API_KEY_STRING" | "/path/to/json" | "JSON_STRING_CONTENT"
        }
        """
        self.project_id = project_id
        self.region = region
        self.model_name = model_name
        self.auth_config = auth_config
        self._token = None
        self._token_expiry = 0

    def _get_access_token(self):
        """
        Service Account kullanarak OAuth2 token alır. 
        Sadece API Key kullanılıyorsa bu işlem atlanır.
        """
        if not self.auth_config or self.auth_config.get("type") != "service_account":
            return None

        # Token önbellekleme (Basit expiry kontrolü)
        import time
        if self._token and time.time() < self._token_expiry:
            return self._token

        val = self.auth_config["value"]
        try:
            # JSON içerik mi yoksa dosya yolu mu?
            if val.strip().startswith("{"):
                info = json.loads(val)
            else:
                with open(val, 'r') as f:
                    info = json.load(f)

            # google-auth kütüphanesi olmadan minimal OAuth2 akışı
            # Not: Kurumsal ortamlarda 'google-auth' kütüphanesi önerilir.
            # Standart kütüphane ile JWT imzalamak karmaşık olduğu için
            # burada basitleştirilmiş bir yapı kurulmuştur.
            # Gerçek deployment'ta: from google.oauth2 import service_account
            # credentials = service_account.Credentials.from_service_account_info(info)
            # return credentials.token
            return "TOKEN_FROM_SERVICE_ACCOUNT" # Placeholder for internal auth logic
        except Exception as e:
            print(f"[!] Vertex Auth Error: {e}")
            return None

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        # Vertex AI REST API Endpoint
        url = f"https://{self.region}-aiplatform.googleapis.com/v1/projects/{self.project_id}/locations/{self.region}/publishers/google/models/{self.model_name}:streamGenerateContent"
        
        headers = {"Content-Type": "application/json"}
        
        # Kimlik doğrulama seçimi
        if self.auth_config and self.auth_config.get("type") == "api_key":
            url += f"?key={self.auth_config['value']}"
        else:
            token = self._get_access_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"

        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": f"{system_prompt}\n\nUser Request: {prompt}"}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
            }
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode())
                # Stream response'u düz metne çevir
                return "".join([chunk["candidates"][0]["content"]["parts"][0]["text"] for chunk in res_data])
        except Exception as e:
            return f"Error: {str(e)}"

class OpenRouterConnector(AIConnector):
    """OpenRouter üzerinden farklı LLM'lere erişim sağlar."""
    def __init__(self, api_key: str, model: str = "google/gemini-pro-1.5"):
        self.api_key = api_key
        self.model = model

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        }
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode())
                return res_data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Error: {str(e)}"

class OllamaConnector(AIConnector):
    """Yerel Ollama kurulumu ile iletişim kurar."""
    def __init__(self, host: str = "http://localhost:11434", model: str = "gemma2"):
        self.host = host
        self.model = model

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        url = f"{self.host}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode())
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode())
                return res_data["message"]["content"]
        except Exception as e:
            return f"Error: {str(e)}"

class AIProviderFactory:
    """Kullanıcı tercihlerine göre doğru connector'ı üretir."""
    @staticmethod
    def create_connector(provider_config: dict) -> AIConnector:
        provider = provider_config.get("provider", "vertex").lower()
        
        if provider == "vertex":
            return VertexAIConnector(
                project_id=provider_config["project_id"],
                region=provider_config.get("region", "us-central1"),
                model_name=provider_config.get("model", "gemini-1.5-pro"),
                auth_config=provider_config.get("auth")
            )
        elif provider == "openrouter":
            return OpenRouterConnector(
                api_key=provider_config["api_key"],
                model=provider_config.get("model", "google/gemini-pro-1.5")
            )
        elif provider == "ollama":
            return OllamaConnector(
                host=provider_config.get("host", "http://localhost:11434"),
                model=provider_config.get("model", "gemma2")
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")
