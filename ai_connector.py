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
            if isinstance(val, dict):
                info = val
            elif val.strip().startswith("{"):
                info = json.loads(val)
            else:
                with open(val, 'r') as f:
                    info = json.load(f)

            now = int(time.time())
            header = {'alg': 'RS256', 'typ': 'JWT'}
            claim = {
                'iss': info['client_email'],
                'sub': info['client_email'],
                'aud': 'https://oauth2.googleapis.com/token',
                'scope': 'https://www.googleapis.com/auth/cloud-platform',
                'exp': now + 3600,
                'iat': now
            }

            def b64url(data):
                if isinstance(data, str):
                    data = data.encode('utf-8')
                elif isinstance(data, dict):
                    data = json.dumps(data).encode('utf-8')
                return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

            segments = [b64url(header), b64url(claim)]
            signing_input = '.'.join(segments).encode('utf-8')

            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key = serialization.load_pem_private_key(
                info['private_key'].encode('utf-8'),
                password=None
            )
            sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            jwt_token = '.'.join(segments + [base64.urlsafe_b64encode(sig).rstrip(b'=').decode('utf-8')])

            token_data = urllib.parse.urlencode({
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': jwt_token
            }).encode('utf-8')

            req = urllib.request.Request(
                'https://oauth2.googleapis.com/token',
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                res = json.loads(resp.read().decode('utf-8'))
                self._token = res['access_token']
                self._token_expiry = now + int(res.get('expires_in', 3600)) - 60
                return self._token
        except Exception as e:
            print(f"[!] Vertex Auth Error: {e}")
            return None

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        # Vertex AI REST API Endpoint
        loc = self.region if self.region else "global"
        prefix = f"https://{loc}-aiplatform.googleapis.com" if loc != "global" else "https://aiplatform.googleapis.com"
        url = f"{prefix}/v1/projects/{self.project_id}/locations/{loc}/publishers/google/models/{self.model_name}:generateContent"
        
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
            with urllib.request.urlopen(req, timeout=45) as response:
                res_data = json.loads(response.read().decode())
                if "candidates" in res_data and len(res_data["candidates"]) > 0:
                    parts = res_data["candidates"][0].get("content", {}).get("parts", [])
                    return "".join([p.get("text", "") for p in parts])
                return json.dumps(res_data)
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
