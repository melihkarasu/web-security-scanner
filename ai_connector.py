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
# Desteklenen Sağlayıcılar:
# 1. OpenAI Compatible (OpenAI, DeepSeek, Groq, Mistral, vLLM, LM Studio vb.)
# 2. Google Vertex AI (Bölge: global, Modeller: gemini-3.1-pro, gemini-3.8-flash)
# 3. Google Gemini API (Google AI Studio, Modeller: gemini-3.1-pro, gemini-3.8-flash)
# 4. OpenRouter
# 5. Ollama (Yerel / Host)
# =============================================================

class AIConnector(ABC):
    """Tüm AI sağlayıcıları için temel soyutlama sınıfı."""
    @abstractmethod
    def chat(self, prompt: str, system_prompt: str = "") -> str:
        pass

    def test_connection(self) -> dict:
        """Sağlayıcı bağlantısını test eder."""
        try:
            res = self.chat("PING: Reply with only 'PONG'", system_prompt="You are a health check assistant. Answer briefly.")
            if res and not res.startswith("Error:"):
                return {"success": True, "message": f"Bağlantı başarılı. Yanıt: {res[:60].strip()}"}
            return {"success": False, "error": res}
        except Exception as e:
            return {"success": False, "error": str(e)}

class OpenAICompatibleConnector(AIConnector):
    """
    OpenAI Uyumlu REST API Connector.
    OpenAI, DeepSeek, Groq, Mistral, vLLM, Ollama OpenAI endpoint vb. ile çalışır.
    """
    def __init__(self, api_key: str = "", base_url: str = "https://api.openai.com/v1", model: str = "gpt-4o"):
        self.api_key = (api_key or "").strip()
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = (model or "gpt-4o").strip()

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choices = res_data.get("choices", [])
                if choices and "message" in choices[0]:
                    return choices[0]["message"].get("content", "")
                return json.dumps(res_data)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            return f"Error: HTTP {e.code} - {err_body}"
        except Exception as e:
            return f"Error: {str(e)}"

class VertexAIConnector(AIConnector):
    """
    Google Vertex AI entegrasyonu.
    Bölge: global (önerilen ve varsayılan).
    Modeller: gemini-3.1-pro, gemini-3.8-flash vb.
    Hem API Key hem de Service Account (JSON içerik veya dosya) destekler.
    """
    def __init__(self, project_id: str, region: str = "global", 
                 model_name: str = "gemini-3.1-pro", 
                 auth_config: dict = None):
        self.project_id = (project_id or "").strip()
        self.region = (region or "global").strip().lower()
        self.model_name = (model_name or "gemini-3.1-pro").strip()
        self.auth_config = auth_config or {}
        self._token = None
        self._token_expiry = 0

    def _get_access_token(self):
        """Service Account kullanarak OAuth2 Bearer token üretir."""
        if not self.auth_config or self.auth_config.get("type") != "service_account":
            return None

        import time
        if self._token and time.time() < self._token_expiry:
            return self._token

        val = self.auth_config.get("value", "")
        try:
            if isinstance(val, dict):
                info = val
            elif isinstance(val, str) and val.strip().startswith("{"):
                info = json.loads(val)
            elif isinstance(val, str) and os.path.exists(val):
                with open(val, "r", encoding="utf-8") as f:
                    info = json.load(f)
            else:
                raise ValueError("Geçersiz Service Account JSON formatı veya dosya bulunamadı.")

            now = int(time.time())
            header = {"alg": "RS256", "typ": "JWT"}
            claim = {
                "iss": info["client_email"],
                "sub": info["client_email"],
                "aud": "https://oauth2.googleapis.com/token",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "exp": now + 3600,
                "iat": now
            }

            def b64url(data):
                if isinstance(data, str):
                    data = data.encode("utf-8")
                elif isinstance(data, dict):
                    data = json.dumps(data).encode("utf-8")
                return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

            segments = [b64url(header), b64url(claim)]
            signing_input = ".".join(segments).encode("utf-8")

            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key = serialization.load_pem_private_key(
                info["private_key"].encode("utf-8"),
                password=None
            )
            sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            jwt_token = ".".join(segments + [base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")])

            token_data = urllib.parse.urlencode({
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jwt_token
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://oauth2.googleapis.com/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                self._token = res["access_token"]
                self._token_expiry = now + int(res.get("expires_in", 3600)) - 60
                return self._token
        except Exception as e:
            print(f"[!] Vertex Auth Error: {e}")
            return None

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        loc = self.region if (self.region and self.region != "global") else "global"
        prefix = f"https://{loc}-aiplatform.googleapis.com" if loc != "global" else "https://aiplatform.googleapis.com"
        url = f"{prefix}/v1/projects/{self.project_id}/locations/{loc}/publishers/google/models/{self.model_name}:generateContent"

        headers = {"Content-Type": "application/json"}
        auth_type = self.auth_config.get("type") if self.auth_config else "api_key"

        if auth_type == "api_key":
            api_key = self.auth_config.get("value", "")
            url += f"?key={api_key}"
        else:
            token = self._get_access_token()
            if not token:
                return "Error: Vertex Service Account token alınamadı. 'cryptography' paketi ve JSON geçerliliğini kontrol edin."
            headers["Authorization"] = f"Bearer {token}"

        user_content = f"{system_prompt}\n\nKullanıcı İstemi: {prompt}" if system_prompt else prompt
        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": user_content}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
            }
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                if "candidates" in res_data and len(res_data["candidates"]) > 0:
                    parts = res_data["candidates"][0].get("content", {}).get("parts", [])
                    return "".join([p.get("text", "") for p in parts])
                return json.dumps(res_data)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            return f"Error: Vertex HTTP {e.code} - {err_body}"
        except Exception as e:
            return f"Error: {str(e)}"

class GeminiAPIConnector(AIConnector):
    """
    Google AI Studio doğrudan Gemini API entegrasyonu.
    Modeller: gemini-3.1-pro, gemini-3.8-flash vb.
    Doğrudan API anahtarı (AIza...) ile çalışır.
    """
    def __init__(self, api_key: str, model_name: str = "gemini-3.1-pro"):
        self.api_key = (api_key or "").strip()
        self.model_name = (model_name or "gemini-3.1-pro").strip()

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}

        user_content = f"{system_prompt}\n\nİstek: {prompt}" if system_prompt else prompt
        payload = {
            "contents": [{
                "role": "user",
                "parts": [{"text": user_content}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048
            }
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                if "candidates" in res_data and len(res_data["candidates"]) > 0:
                    parts = res_data["candidates"][0].get("content", {}).get("parts", [])
                    return "".join([p.get("text", "") for p in parts])
                return json.dumps(res_data)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            return f"Error: Gemini API HTTP {e.code} - {err_body}"
        except Exception as e:
            return f"Error: {str(e)}"

class OpenRouterConnector(AIConnector):
    """OpenRouter üzerinden LLM modellerine erişim sağlar."""
    def __init__(self, api_key: str, model: str = "google/gemini-3.1-pro"):
        self.api_key = (api_key or "").strip()
        self.model = (model or "google/gemini-3.1-pro").strip()

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages
        }
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                return res_data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Error: {str(e)}"

class OllamaConnector(AIConnector):
    """Yerel veya Docker ağı üzerindeki Ollama kurulumu ile iletişim kurar."""
    def __init__(self, host: str = "http://localhost:11434", model: str = "gemma2"):
        self.host = (host or "http://localhost:11434").rstrip("/")
        self.model = (model or "gemma2").strip()

    def chat(self, prompt: str, system_prompt: str = "") -> str:
        url = f"{self.host}/api/chat"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False
        }
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"))
            with urllib.request.urlopen(req, timeout=60) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                return res_data["message"]["content"]
        except Exception as e:
            return f"Error: {str(e)}"

class AIProviderFactory:
    """Kullanıcı tercihlerine göre doğru connector örneğini üretir."""
    @staticmethod
    def create_connector(provider_config: dict) -> AIConnector:
        provider = (provider_config.get("provider") or "openai").lower().strip()

        if provider in ("openai", "openai_compatible", "custom"):
            return OpenAICompatibleConnector(
                api_key=provider_config.get("api_key") or provider_config.get("auth", {}).get("value") or "",
                base_url=provider_config.get("base_url") or "https://api.openai.com/v1",
                model=provider_config.get("model") or "gpt-4o"
            )
        elif provider == "vertex":
            auth = provider_config.get("auth")
            if not isinstance(auth, dict):
                # Geriye dönük uyumluluk veya düz string
                auth = {"type": "service_account" if "{" in str(auth) else "api_key", "value": auth}
            return VertexAIConnector(
                project_id=provider_config.get("project_id", ""),
                region=provider_config.get("region") or "global",
                model_name=provider_config.get("model") or "gemini-3.1-pro",
                auth_config=auth
            )
        elif provider in ("gemini", "gemini_api", "google"):
            api_key = provider_config.get("api_key") or provider_config.get("auth", {}).get("value") or ""
            return GeminiAPIConnector(
                api_key=api_key,
                model_name=provider_config.get("model") or "gemini-3.1-pro"
            )
        elif provider == "openrouter":
            return OpenRouterConnector(
                api_key=provider_config.get("api_key") or provider_config.get("auth", {}).get("value") or "",
                model=provider_config.get("model") or "google/gemini-3.1-pro"
            )
        elif provider == "ollama":
            return OllamaConnector(
                host=provider_config.get("host") or provider_config.get("base_url") or "http://localhost:11434",
                model=provider_config.get("model") or "gemma2"
            )
        else:
            raise ValueError(f"Desteklenmeyen AI sağlayıcısı: {provider}")
