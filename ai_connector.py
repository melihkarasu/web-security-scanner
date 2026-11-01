import json
import os
import base64
import hashlib
import hmac
import socket
import time
import urllib.request
import urllib.parse
import urllib.error
from abc import ABC, abstractmethod

from redaction import redact_text
from json_utils import extract_json_detail, looks_like_error

# Reasoning modeller (DeepSeek-R1, Evren vb.) 60 sn'yi aşabiliyor — geniş timeout
# + tek otomatik tekrar deneme (yalnızca ağ/timeout hatalarında; HTTP hatalarında değil)
LLM_TIMEOUT = 180


def _urlopen_with_retry(req, timeout=LLM_TIMEOUT, retries=3):
    last_err = None
    for attempt in range(retries + 1):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < retries:
                time.sleep(3 * (attempt + 1))
                last_err = e
                continue
            raise
        except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
            last_err = e
            time.sleep(2 * (attempt + 1))
    raise last_err


def _usage_from_openai(res_data):
    u = res_data.get("usage") or {}
    return {"input_tokens": u.get("prompt_tokens"), "output_tokens": u.get("completion_tokens"),
            "total_tokens": u.get("total_tokens")}


_DROPPABLE_PARAMS = (
    ("temperature", ("temperature",)),
    ("response_format", ("response_format", "json_object", "json mode", "json_mode", "responseformat")),
)


def _post_json_adaptive(conn, url, headers, payload, label):
    """JSON POST. HTTP 400/422 isteğe bağlı bir parametreyi (temperature / response_format) reddederse
    o parametre olmadan bir kez daha dener ve bağlayıcı nesnesinde hatırlar (sonraki çağrılarda gönderilmez).

    Örnek: Claude 5.x ve bazı akıl yürüten modeller 'temperature'ı, bazı OpenAI-uyumlu sunucular
    'response_format'ı (JSON modu) reddeder. Döner: (yanıt_sözlüğü, None) ya da (None, "Error: ...").
    """
    dropped = conn.__dict__.setdefault("_dropped_params", set())
    body = {k: v for k, v in payload.items() if k not in dropped}
    for _ in range(len(_DROPPABLE_PARAMS) + 1):
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
        try:
            with _urlopen_with_retry(req) as resp:
                return json.loads(resp.read().decode("utf-8")), None
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            low = err.lower()
            victim = None
            if e.code in (400, 422):
                for param, words in _DROPPABLE_PARAMS:
                    if param in body and any(w in low for w in words):
                        victim = param
                        break
            if victim is None:
                return None, "Error: %s HTTP %d - %s" % (label, e.code, err)
            dropped.add(victim)
            body.pop(victim, None)
        except Exception as e:
            return None, "Error: %s" % str(e)
    return None, "Error: %s isteği isteğe bağlı parametreler düşürüldükten sonra da başarısız oldu" % label

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
    """Tüm AI sağlayıcıları için temel soyutlama sınıfı.

    Alt sınıflar yalnızca _chat_impl'i uygular. Telemetri (gecikme, token, başarı) ve
    JSON modu/onarımı (chat_json) burada merkezî olarak yönetilir.
    """

    @abstractmethod
    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
        """Sağlayıcıya özel ham çağrı. json_mode=True ise sağlayıcı JSON modu istenir
        (desteklemeyen sağlayıcılarda chat_json yine de prompt + deterministik onarımla çalışır)."""
        raise NotImplementedError

    def chat(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
        t0 = time.time()
        self._last_usage = {}
        try:
            text = self._chat_impl(prompt, system_prompt, json_mode)
        except Exception as e:
            text = "Error: %s" % e
        self._record_call(t0, text, getattr(self, "_last_usage", {}))
        return text

    def chat_json(self, prompt: str, system_prompt: str = "", want: str = "object", fixer_retry: bool = True) -> dict:
        """JSON bekleyen çağrılar: sağlayıcı JSON modu + deterministik onarım + tek düzeltici tekrar.

        PentAGI'nin tool_call_fixer yaklaşımının uyarlaması. Döner:
        {"data": parsed|None, "raw": str, "ok": bool, "repaired": bool, "fixed": bool}.
        """
        shape = "array" if want == "list" else "object"
        instr = "\n\nReturn ONLY one valid minified JSON %s. No prose, no explanation, no markdown fences." % shape
        raw = self.chat(prompt + instr, system_prompt, json_mode=True)
        parsed, repaired = extract_json_detail(raw, want)
        fixed = False
        if parsed is None and fixer_retry and not looks_like_error(raw):
            fix_prompt = ("The following text was supposed to be a single JSON %s but could not be parsed. "
                          "Return ONLY the corrected, valid JSON %s, nothing else:\n\n%s" % (shape, shape, raw[:6000]))
            fix_raw = self.chat(fix_prompt, "", json_mode=True)
            fparsed, frepaired = extract_json_detail(fix_raw, want)
            if fparsed is not None:
                parsed, repaired, raw, fixed = fparsed, frepaired, fix_raw, True
        return {"data": parsed, "raw": raw, "ok": parsed is not None, "repaired": bool(repaired), "fixed": fixed}

    def json_health_check(self) -> dict:
        """Saglayici/modelin JSON modu uyumlulugunu olcer (PentAGI ctester/ftester uyarlamasi).

        Kucuk bir JSON istegi gonderir; cikti dogrudan mi ayristi, deterministik onarim mi
        gerekti, yoksa duzeltici tekrar mi gerekti raporlar. Kucuk/yerel Ollama modelleri
        arasinda hangisinin guvenilir JSON urettigini secmeye yardimci olur.
        """
        t0 = time.time()
        res = self.chat_json(
            'Return a JSON object with exactly these keys: "status" set to the string "ok" '
            'and "answer" set to the number 42.', want="object")
        data = res.get("data") if isinstance(res.get("data"), dict) else {}
        quality = "parse_failed"
        if res.get("ok"):
            quality = "fixer_retry" if res.get("fixed") else ("repaired" if res.get("repaired") else "clean")
        return {
            "success": bool(res.get("ok")),
            "json_quality": quality,
            "repaired": bool(res.get("repaired")),
            "fixer_retry_used": bool(res.get("fixed")),
            "keys_returned": sorted(list(data.keys()))[:10],
            "latency_ms": int((time.time() - t0) * 1000),
        }

    def _record_call(self, t0, text, usage=None):
        try:
            tele = self.__dict__.setdefault("telemetry", [])
            tele.append({
                "provider": type(self).__name__,
                "model": getattr(self, "model", None) or getattr(self, "model_name", None) or "",
                "agent": getattr(self, "_agent_label", ""),
                "latency_ms": int((time.time() - t0) * 1000),
                "ok": not looks_like_error(text),
                "chars": len(text or ""),
                "usage": {k: v for k, v in (usage or {}).items() if v is not None},
                "ts": int(t0 * 1000),
            })
        except Exception:
            pass

    def pop_usage(self) -> dict:
        return {k: v for k, v in (getattr(self, "_last_usage", {}) or {}).items() if v is not None}

    def get_telemetry(self):
        return self.__dict__.setdefault("telemetry", [])

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

    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
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
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        res_data, err = _post_json_adaptive(self, url, headers, payload, "OpenAI-compatible")
        if err:
            return err
        self._last_usage = _usage_from_openai(res_data)
        choices = res_data.get("choices", [])
        if choices and "message" in choices[0]:
            msg = choices[0]["message"]
            # Reasoning modellerde (DeepSeek-R1 vb.) content boş kalıp reasoning alanında metin dönebilir.
            return msg.get("content") or msg.get("reasoning") or ""
        return json.dumps(res_data)

class VertexAIConnector(AIConnector):
    """
    Google Vertex AI entegrasyonu.
    Bölge: global (önerilen ve varsayılan).
    Modeller: gemini-3.1-pro, gemini-3.8-flash vb.
    Hem API Key hem de Service Account (JSON içerik veya dosya) destekler.
    """
    def __init__(self, project_id: str, region: str = "global", 
                 model_name: str = "gemini-3.8-flash", 
                 auth_config: dict = None):
        self.project_id = (project_id or "").strip()
        self.region = (region or "global").strip().lower()
        raw_model = (model_name or "gemini-3.8-flash").strip()
        if raw_model == "gemini-3.1-pro":
            raw_model = "gemini-3.1-pro-preview"
        self.model_name = raw_model
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

    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
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
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
            with _urlopen_with_retry(req) as response:
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
        m_clean = (model_name or "gemini-3.8-flash").strip()
        if m_clean == "gemini-3.1-pro":
            m_clean = "gemini-3.1-pro-preview"
        self.model_name = m_clean

    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
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
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
            with _urlopen_with_retry(req) as response:
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

    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
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
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        res_data, err = _post_json_adaptive(self, url, headers, payload, "OpenRouter")
        if err:
            return err
        self._last_usage = _usage_from_openai(res_data)
        choices = res_data.get("choices") or []
        if choices and isinstance(choices[0], dict):
            return (choices[0].get("message") or {}).get("content") or ""
        return json.dumps(res_data)

class OllamaConnector(AIConnector):
    """Yerel veya Docker ağı üzerindeki Ollama kurulumu ile iletişim kurar."""
    def __init__(self, host: str = "http://localhost:11434", model: str = "gemma2"):
        self.host = (host or "http://localhost:11434").rstrip("/")
        self.model = (model or "gemma2").strip()

    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
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
        if json_mode:
            payload["format"] = "json"
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"))
            with _urlopen_with_retry(req) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                self._last_usage = {"input_tokens": res_data.get("prompt_eval_count"), "output_tokens": res_data.get("eval_count")}
                return res_data["message"]["content"]
        except Exception as e:
            return f"Error: {str(e)}"

class AnthropicConnector(AIConnector):
    """Dogrudan Anthropic Messages API (Claude) baglayicisi.

    ONEMLI: 'anthropic-workspace-id' basligi VARSAYILAN OLARAK GONDERILMEZ. 2026-10-31'de
    OpenClaw genelinde bu baslik gecersiz bir workspace'e isaret edip tum /v1/messages
    isteklerini HTTP 404 ile reddetmisti. Yalnizca kullanici acikca workspace_id verirse eklenir.
    """

    def __init__(self, api_key, model="claude-sonnet-5-5", base_url="https://api.anthropic.com",
                 max_tokens=4096, workspace_id="", version="2023-06-01"):
        self.api_key = (api_key or "").strip()
        self.model = (model or "claude-sonnet-5-5").strip()
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")
        self.max_tokens = int(max_tokens or 4096)
        self.workspace_id = (workspace_id or "").strip()
        self.version = (version or "2023-06-01").strip()

    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        url = self.base_url + "/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.version,
            "content-type": "application/json",
        }
        if self.workspace_id:
            headers["anthropic-workspace-id"] = self.workspace_id
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        # Not: Claude 5.x "temperature" parametresini reddediyor (HTTP 400 "deprecated"); varsayılan kullanılır.
        if system_prompt:
            body["system"] = system_prompt
        try:
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
            with _urlopen_with_retry(req) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                u = res.get("usage") or {}
                self._last_usage = {"input_tokens": u.get("input_tokens"), "output_tokens": u.get("output_tokens")}
                parts = res.get("content") or []
                return "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        except urllib.error.HTTPError as e:
            return "Error: Anthropic HTTP %d - %s" % (e.code, e.read().decode("utf-8", errors="replace"))
        except Exception as e:
            return "Error: %s" % str(e)


class AzureOpenAIConnector(AIConnector):
    """Azure OpenAI Service baglayicisi (chat completions).

    endpoint ornek: https://<kaynak>.openai.azure.com
    deployment: Azure portalinda tanimli dagitim adi (model adi degil).
    """

    def __init__(self, api_key, endpoint, deployment, api_version="2024-10-21", model=""):
        self.api_key = (api_key or "").strip()
        self.endpoint = (endpoint or "").rstrip("/")
        self.deployment = (deployment or "").strip()
        self.api_version = (api_version or "2024-10-21").strip()
        self.model = (model or self.deployment or "azure-openai").strip()

    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        url = "%s/openai/deployments/%s/chat/completions?api-version=%s" % (
            self.endpoint, urllib.parse.quote(self.deployment), self.api_version)
        headers = {"api-key": self.api_key, "Content-Type": "application/json"}
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        body = {"messages": messages, "temperature": 0.2}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        res, err = _post_json_adaptive(self, url, headers, body, "Azure OpenAI")
        if err:
            return err
        self._last_usage = _usage_from_openai(res)
        choices = res.get("choices", [])
        if choices and "message" in choices[0]:
            return choices[0]["message"].get("content") or ""
        return json.dumps(res)


class AWSBedrockConnector(AIConnector):
    """AWS Bedrock Runtime baglayicisi (varsayilan: Anthropic Claude model ailesi).

    SigV4 imzalama yalnizca Python standart kutuphanesiyle (hmac, hashlib) yapilir.
    model_id ornek: anthropic.claude-3-5-sonnet-20241022-v2:0
    """

    def __init__(self, access_key, secret_key, region="us-east-1",
                 model_id="anthropic.claude-3-5-sonnet-20241022-v2:0",
                 session_token="", max_tokens=4096):
        self.access_key = (access_key or "").strip()
        self.secret_key = (secret_key or "").strip()
        self.region = (region or "us-east-1").strip()
        self.model_id = (model_id or "").strip()
        self.model = self.model_id
        self.session_token = (session_token or "").strip()
        self.max_tokens = int(max_tokens or 4096)

    def _build_payload(self, prompt, system_prompt):
        if self.model_id.startswith("anthropic."):
            payload = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if not getattr(self, "_no_temperature", False):
                payload["temperature"] = 0.2
            if system_prompt:
                payload["system"] = system_prompt
            return payload
        text = (system_prompt + "\n\n" + prompt) if system_prompt else prompt
        return {"prompt": text, "max_tokens": self.max_tokens}

    def _sigv4_headers(self, host, canonical_uri, body, when=None):
        import hashlib
        service = "bedrock"
        now = when or time.gmtime()
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", now)
        date_stamp = time.strftime("%Y%m%d", now)
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_headers = "content-type:application/json\nhost:%s\nx-amz-date:%s\n" % (host, amz_date)
        signed_headers = "content-type;host;x-amz-date"
        if self.session_token:
            canonical_headers += "x-amz-security-token:%s\n" % self.session_token
            signed_headers = "content-type;host;x-amz-date;x-amz-security-token"
        canonical_request = "\n".join(
            ["POST", canonical_uri, "", canonical_headers, signed_headers, payload_hash])
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "%s/%s/%s/aws4_request" % (date_stamp, self.region, service)
        string_to_sign = "\n".join([
            algorithm, amz_date, credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])

        def _sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _sign(("AWS4" + self.secret_key).encode("utf-8"), date_stamp)
        k_region = _sign(k_date, self.region)
        k_service = _sign(k_region, service)
        k_signing = _sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
            algorithm, self.access_key, credential_scope, signed_headers, signature)
        headers = {
            "Content-Type": "application/json",
            "X-Amz-Date": amz_date,
            "Authorization": authorization,
            "Accept": "application/json",
        }
        if self.session_token:
            headers["X-Amz-Security-Token"] = self.session_token
        return headers

    def _chat_impl(self, prompt, system_prompt="", json_mode=False):
        host = "bedrock-runtime.%s.amazonaws.com" % self.region
        wire_path = "/model/%s/invoke" % urllib.parse.quote(self.model_id, safe="")
        # SigV4: S3 dışındaki servislerde kanonik URI'deki yol İKİ KEZ kodlanır
        # (model kimliğindeki ':' → telde %3A, imzada %253A); aksi hâlde SignatureDoesNotMatch.
        canonical_uri = urllib.parse.quote(wire_path, safe="/~")
        endpoint = "https://%s%s" % (host, wire_path)
        body = json.dumps(self._build_payload(prompt, system_prompt)).encode("utf-8")
        try:
            headers = self._sigv4_headers(host, canonical_uri, body)
            req = urllib.request.Request(endpoint, data=body, headers=headers)
            with _urlopen_with_retry(req) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                if isinstance(res.get("content"), list):
                    u = res.get("usage") or {}
                    self._last_usage = {"input_tokens": u.get("input_tokens"), "output_tokens": u.get("output_tokens")}
                    return "".join(p.get("text", "") for p in res["content"] if isinstance(p, dict))
                for key in ("completion", "generation", "outputText"):
                    if key in res:
                        return res[key]
                if res.get("results"):
                    return res["results"][0].get("outputText", "")
                return json.dumps(res)
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            if e.code == 400 and "temperature" in err.lower() and not getattr(self, "_no_temperature", False):
                # Claude 5.x (Bedrock dahil) 'temperature'ı reddediyor → parametresiz, yeniden imzalanmış tek tekrar
                self._no_temperature = True
                return self._chat_impl(prompt, system_prompt, json_mode)
            return "Error: Bedrock HTTP %d - %s" % (e.code, err)
        except Exception as e:
            return "Error: %s" % str(e)


class RedactingConnector(AIConnector):
    """LLM'e giden prompt ve sistem prompt'unu sır maskelemesinden geçiren sarmalayıcı.

    PentAGI'deki GetSecretPatterns maskelemesinin bu araca uyarlanmış hâli: hedeften gelen
    çerez/başlık/gövde verisi ve SAST kod kesitlerindeki sırlar bulut veya yerel LLM'e
    gitmeden maskelenir. Yanıt dokunulmadan döner; diğer öznitelikler alttaki bağlayıcıya
    yönlendirilir.
    """

    def __init__(self, inner):
        self._inner = inner

    def _chat_impl(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
        return self._inner.chat(prompt, system_prompt, json_mode=json_mode)

    def chat(self, prompt: str, system_prompt: str = "", json_mode: bool = False) -> str:
        # Ajan etiketini telemetrinin kaydedildigi ic baglayiciya tasi
        try:
            self._inner._agent_label = getattr(self, "_agent_label", "")
        except Exception:
            pass
        return self._inner.chat(redact_text(prompt),
                                redact_text(system_prompt) if system_prompt else system_prompt,
                                json_mode=json_mode)

    def pop_usage(self) -> dict:
        return self._inner.pop_usage() if hasattr(self._inner, "pop_usage") else {}

    def get_telemetry(self):
        return getattr(self._inner, "telemetry", [])

    def __getattr__(self, name):
        if name == "_inner":
            raise AttributeError(name)
        return getattr(self._inner, name)


def _with_bedrock_credentials(cfg):
    """UI'daki tek kimlik alanından (auth.value / api_key) AWS anahtarlarını ayrıştırır.

    Kabul edilen biçimler: JSON {"access_key","secret_key","session_token"} (veya aws_* adları)
    ya da "ERİŞİM_ANAHTARI:GİZLİ_ANAHTAR[:OTURUM_TOKENI]". Açık alanlar verilmişse dokunulmaz.
    """
    cfg = dict(cfg or {})
    if cfg.get("access_key") or cfg.get("aws_access_key_id"):
        return cfg
    auth = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else {}
    raw = str(cfg.get("api_key") or auth.get("value") or "").strip()
    if not raw:
        return cfg
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            data = {}
        if isinstance(data, dict):
            for src, dst in (("access_key", "access_key"), ("aws_access_key_id", "access_key"),
                             ("secret_key", "secret_key"), ("aws_secret_access_key", "secret_key"),
                             ("session_token", "session_token"), ("aws_session_token", "session_token")):
                if data.get(src) and not cfg.get(dst):
                    cfg[dst] = str(data[src]).strip()
        return cfg
    parts = raw.split(":")
    if len(parts) >= 2:
        cfg["access_key"] = parts[0].strip()
        cfg["secret_key"] = parts[1].strip()
        if len(parts) >= 3:
            cfg["session_token"] = ":".join(parts[2:]).strip()
    return cfg


class AIProviderFactory:
    """Kullanıcı tercihlerine göre doğru connector örneğini üretir."""
    @staticmethod
    def create_connector(provider_config: dict) -> AIConnector:
        """Sağlayıcı bağlayıcısını oluşturur ve sır maskeleme katmanıyla sarar.

        AI Red Team hattı, SAST AI denetimi ve bağlantı testi bu fabrikayı kullandığı için
        LLM'e giden tüm metinler tek noktadan maskelenir (bkz. redaction.py).
        """
        return RedactingConnector(AIProviderFactory._create_raw_connector(provider_config))

    @staticmethod
    def _create_raw_connector(provider_config: dict) -> AIConnector:
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
        elif provider == "anthropic":
            return AnthropicConnector(
                api_key=provider_config.get("api_key") or provider_config.get("auth", {}).get("value") or "",
                model=provider_config.get("model") or "claude-sonnet-5-5",
                base_url=provider_config.get("base_url") or "https://api.anthropic.com",
                max_tokens=provider_config.get("max_tokens") or 4096,
                workspace_id=provider_config.get("workspace_id") or ""
            )
        elif provider in ("azure", "azure_openai"):
            return AzureOpenAIConnector(
                api_key=provider_config.get("api_key") or provider_config.get("auth", {}).get("value") or "",
                endpoint=provider_config.get("endpoint") or provider_config.get("base_url") or "",
                deployment=provider_config.get("deployment") or provider_config.get("model") or "",
                api_version=provider_config.get("api_version") or "2024-10-21",
                model=provider_config.get("model") or ""
            )
        elif provider in ("bedrock", "aws_bedrock", "aws"):
            provider_config = _with_bedrock_credentials(provider_config)
            return AWSBedrockConnector(
                access_key=provider_config.get("access_key") or provider_config.get("aws_access_key_id") or "",
                secret_key=provider_config.get("secret_key") or provider_config.get("aws_secret_access_key") or "",
                region=provider_config.get("region") or "us-east-1",
                model_id=provider_config.get("model_id") or provider_config.get("model") or "anthropic.claude-3-5-sonnet-20241022-v2:0",
                session_token=provider_config.get("session_token") or "",
                max_tokens=provider_config.get("max_tokens") or 4096
            )
        else:
            raise ValueError(f"Desteklenmeyen AI sağlayıcısı: {provider}")
