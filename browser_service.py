#!/usr/bin/env python3
"""
browser_service.py — Yalıtılmış gerçek tarayıcı yan konteyneri (wss-browser) için HTTP servisi (Faz 5).

PentAGI'deki ayrı "scraper" konteynerinin uyarlaması: Chromium bu konteynerde çalışır; scanner
konteynerinde (çalışma alanı ve bulut kimlik bilgileri bağlı) hiçbir tarayıcı süreci açılmaz.
Docker'ın varsayılan seccomp profili Chromium'un namespace sandbox'ına izin vermediği için burada
Chromium --no-sandbox çalışır; yalıtım konteyner düzeyindedir: bağlı dosya / kimlik bilgisi / Docker
soketi yok, tüm Linux yetenekleri düşürülmüş, kök dosya sistemi salt-okunur, no-new-privileges,
bellek ve süreç sınırı (bkz. docker-compose.browser.yml).
  - Uçlar: GET /health (açık), GET /capabilities, POST /render, POST /confirm_xss (anahtar gerekli).
  - Anahtar: WSS_BROWSER_SERVICE_TOKEN ya da her açılışta üretilip WSS_BROWSER_SERVICE_TOKEN_FILE'a
    (scanner ile paylaşılan volume) 0600 izinle yazılır.
  - Her istek kendi kapsam kilitli vekili ve geçici profiliyle yeni bir oturum açar (aynı anda en fazla 2).
Yalnızca Python standart kütüphanesi kullanır.
"""

import hmac
import json
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import headless_browser as hb

MAX_BODY = 64 * 1024
MAX_BUDGET = hb.DEFAULT_SESSION_BUDGET
_PARAM_RE = re.compile(r"^[\w.\-\[\]]{1,100}$")
_SLOTS = threading.BoundedSemaphore(2)
_STATE = {"key": ""}


def _load_or_create_key():
    value = os.environ.get("WSS_BROWSER_SERVICE_TOKEN", "").strip()
    if value:
        return value
    value = secrets.token_urlsafe(32)
    path = os.environ.get("WSS_BROWSER_SERVICE_TOKEN_FILE", "").strip()
    if path:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value)
        os.replace(tmp, path)
    return value


class BrowserServiceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WSS-BrowserService/1.0"

    def log_message(self, *args):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _authorized(self):
        supplied = (self.headers.get("X-WSS-Browser-Token") or "").strip()
        expected = _STATE["key"]
        return bool(supplied and expected) and hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if self.path == "/capabilities":
            if not self._authorized():
                return self._send(401, {"ok": False, "error": "Geçersiz tarayıcı servis anahtarı."})
            return self._send(200, {"ok": True, "capabilities": hb.capabilities(local=True)})
        return self._send(404, {"ok": False, "error": "Bilinmeyen uç."})

    def do_POST(self):
        if self.path not in ("/render", "/confirm_xss"):
            return self._send(404, {"ok": False, "error": "Bilinmeyen uç."})
        if not self._authorized():
            return self._send(401, {"ok": False, "error": "Geçersiz tarayıcı servis anahtarı."})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._send(400, {"ok": False, "error": "Geçersiz istek gövdesi boyutu."})
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            data = None
        if not isinstance(data, dict):
            return self._send(400, {"ok": False, "error": "Geçersiz JSON."})
        param = str(data.get("param") or "")
        if self.path == "/confirm_xss" and not _PARAM_RE.match(param):
            return self._send(400, {"ok": False, "error": "Geçersiz parametre adı."})
        try:
            budget = max(1, min(MAX_BUDGET, int(data.get("budget") or MAX_BUDGET)))
        except (TypeError, ValueError):
            budget = MAX_BUDGET
        if not _SLOTS.acquire(timeout=90):
            return self._send(503, {"ok": False, "error": "Tarayıcı servisi meşgul."})
        try:
            with hb.BrowserSession(str(data.get("scope_url") or ""), budget=budget) as session:
                if self.path == "/render":
                    result = session.render(str(data.get("url") or ""), screenshot=bool(data.get("screenshot")))
                else:
                    result = session.confirm_xss(str(data.get("url") or ""), param,
                                                 screenshot=data.get("screenshot", True) is not False)
                stats = session.stats()
            return self._send(200, {"ok": True, "result": result, "stats": stats})
        except hb.BrowserUnavailable as e:
            return self._send(503, {"ok": False, "error": str(e)})
        except Exception as e:
            return self._send(500, {"ok": False, "error": "Tarayıcı servisi hatası: %s" % str(e)[:200]})
        finally:
            _SLOTS.release()


def make_server(host="127.0.0.1", port=0):
    _STATE["key"] = _load_or_create_key()
    server = ThreadingHTTPServer((host, port), BrowserServiceHandler)
    server.daemon_threads = True
    return server


def main():
    host = os.environ.get("WSS_BROWSER_SERVICE_HOST", "0.0.0.0")
    port = int(os.environ.get("WSS_BROWSER_SERVICE_PORT", "9230"))
    server = make_server(host, port)
    caps = hb.capabilities(refresh=True, local=True)
    print("WSS tarayıcı servisi %s:%d — Chromium: %s %s (kullanılabilir=%s, sandbox=%s)%s" % (
        host, port, caps.get("binary", "-"), caps.get("version", ""), caps.get("available"), caps.get("sandbox", "-"),
        "" if caps.get("available") else " — " + str(caps.get("reason", ""))), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
