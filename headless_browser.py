#!/usr/bin/env python3
"""
headless_browser.py — İsteğe bağlı gerçek tarayıcı motoru: headless Chromium (Faz 5).

PentAGI'deki izole tarayıcının (scraper) bu araca uyarlanmış hâli. Chromium ikili dosyası
dışında ek paket gerektirmez; yalnızca Python standart kütüphanesi kullanır:
  - Sayfayı gerçek tarayıcıda çizer: JavaScript ile oluşan bağlantı ve formlar görünür (SPA keşfi).
  - Kodlanmadan yansıyan XSS'in tarayıcıda GERÇEKTEN çalıştığını zararsız bir işaretle kanıtlar
    ve ekran görüntüsü alır.
  - Tarayıcının tüm trafiği kapsam kilitli yerel bir vekil sunucudan (proxy) geçer: yalnızca etik
    onaylı köken (scheme + host + port); http'de yalnızca GET / HEAD / OPTIONS; tarama başına
    istek bütçesi. Başka adreslere (iç ağ IP'leri dahil) giden istekler reddedilir. Tarayıcıda DNS
    çözümlemesi kapatılır, WebRTC UDP sızıntısı engellenir, her çizim geçici bir profil kullanır.
  - Chromium sandbox'ı açık çalışır. Sandbox kullanılamıyorsa --no-sandbox yalnızca
    WSS_BROWSER_NO_SANDBOX=1 ile açıkça izin verildiğinde kullanılır. Süreç root ise Chromium
    yetkisiz bir kullanıcıyla (varsayılan uid 1000) başlatılır.
Varsayılan olarak KAPALIDIR; tarama isteğinde real_browser bayrağıyla açılır.
"""

import base64
import glob
import http.client
import os
import re
import secrets
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import pwd
except ImportError:  # Windows
    pwd = None

from safety_guard import is_in_scope, normalize_origin, validate_probe_payload

RENDER_TIMEOUT_SECONDS = 45
VIRTUAL_TIME_BUDGET_MS = 5000
DEFAULT_SESSION_BUDGET = 100
MAX_DOM_BYTES = 4 * 1024 * 1024
MAX_SCREENSHOT_BYTES = 3 * 1024 * 1024
MAX_UPSTREAM_BODY = 15 * 1024 * 1024
MAX_REQUEST_BODY = 1024 * 1024
PACE_SECONDS = 0.05
TUNNEL_IDLE_SECONDS = 30
ALLOWED_HTTP_METHODS = ("GET", "HEAD", "OPTIONS")
XSS_PROOF_ATTR = "data-wzx-exec"
_HOP_BY_HOP = frozenset(("connection", "keep-alive", "proxy-connection", "proxy-authenticate",
                         "proxy-authorization", "te", "trailer", "trailers", "transfer-encoding", "upgrade"))
_SANDBOX_ERR = re.compile(r"no usable sandbox|sandbox|zygote|setuid|running as root", re.I)

# Zararsız XSS kanıt işareti: yalnızca BİZİM headless tarayıcımızdaki DOM'u değiştirir
# (html etiketine data-wzx-exec="<nonce>" ekler ve ekran görüntüsü için kırmızı bir bant koyar).
XSS_PROOF_PAYLOAD = (
    "\"'><img src=x onerror=\""
    "var d=document.createElement('div');d.id='wzx-proof';"
    "d.textContent='WSS XSS PROOF NONCE';"
    "d.style.cssText='position:relative;z-index:2147483647;background:#b91c1c;color:#fff;"
    "font:700 22px sans-serif;padding:14px';"
    "(document.body||document.documentElement).prepend(d);"
    "document.documentElement.setAttribute('data-wzx-exec','NONCE')\">"
)

_COMMON_FLAGS = [
    "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
    "--disable-extensions", "--disable-background-networking", "--disable-component-update",
    "--disable-sync", "--disable-default-apps", "--disable-domain-reliability",
    "--disable-client-side-phishing-detection", "--disable-breakpad", "--metrics-recording-only",
    "--mute-audio", "--hide-scrollbars", "--window-size=1280,900",
    "--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,"
    "AutofillServerCommunication,CertificateTransparencyComponentUpdater",
    # Tüm trafik kapsam vekilinden geçer (loopback dahil); tarayıcı kendisi DNS çözümlemez.
    "--proxy-bypass-list=<-loopback>",
    # Not: EXCLUDE olmadan kural vekilin kendi adresini (127.0.0.1) de eşler ve tarayıcı hiçbir yere bağlanamaz.
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--ignore-certificate-errors",
]

_CAPS_CACHE = {}
_CAPS_LOCK = threading.Lock()


class BrowserUnavailable(Exception):
    """Gerçek tarayıcı bu kurulumda kullanılamıyor."""


def browser_enabled_default():
    return os.environ.get("WSS_REAL_BROWSER", "0").strip().lower() in ("1", "true", "yes", "on")


def _no_sandbox_allowed():
    return os.environ.get("WSS_BROWSER_NO_SANDBOX", "").strip().lower() in ("1", "true", "yes", "on")


def _version_key(path):
    m = re.search(r"-(\d+)" + re.escape(os.sep), path)
    return int(m.group(1)) if m else 0


def find_chromium():
    """WSS_CHROMIUM_PATH → PATH (chrome-headless-shell, chromium, google-chrome) → Playwright önbelleği."""
    env_path = os.environ.get("WSS_CHROMIUM_PATH", "").strip()
    if env_path:
        return env_path if os.path.isfile(env_path) and os.access(env_path, os.X_OK) else None
    for name in ("chrome-headless-shell", "chromium-headless-shell", "headless_shell", "chromium", "chromium-browser",
                 "google-chrome-stable", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if not root or root == "0":
        root = os.path.join(os.path.expanduser("~"), ".cache", "ms-playwright")
    for pattern in (os.path.join(root, "chromium_headless_shell-*", "chrome-*", "chrome-headless-shell"),
                    os.path.join(root, "chromium_headless_shell-*", "chrome-*", "headless_shell"),
                    os.path.join(root, "chromium-*", "chrome-linux*", "chrome")):
        candidates = [c for c in glob.glob(pattern) if os.access(c, os.X_OK)]
        if candidates:
            return max(candidates, key=_version_key)
    return None


def _is_headless_shell(path):
    return os.path.basename(path or "") in ("chrome-headless-shell", "chromium-headless-shell", "headless_shell")


def _run_as_user():
    """Süreç root ise Chromium'u yetkisiz bir kullanıcıyla başlatmak için (uid, gid); değilse None."""
    if os.name != "posix" or os.geteuid() != 0 or pwd is None:
        return None
    try:
        entry = pwd.getpwuid(int(os.environ.get("WSS_BROWSER_UID", "1000")))
        return (entry.pw_uid, entry.pw_gid)
    except (KeyError, ValueError):
        return None


def _chromium_version(path):
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15,
                             stdin=subprocess.DEVNULL)
        text = (out.stdout or out.stderr or "").strip()
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
        return m.group(1) if m else text[:60]
    except Exception:
        return ""


def _spawn(args, profile, run_as, timeout):
    """Chromium'u yalıtılmış ortamla başlatır; zaman aşımında tüm süreç grubunu öldürür."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": profile, "TMPDIR": profile, "LANG": "C.UTF-8"}
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "stdin": subprocess.DEVNULL,
              "env": env, "start_new_session": True}
    if run_as:
        kwargs.update(user=run_as[0], group=run_as[1], extra_groups=[])
    proc = subprocess.Popen(args, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        out, err = proc.communicate()
        return -9, out, err, True


def _self_test(path, run_as, no_sandbox):
    """Küçük bir data: sayfasını çizer: (çalışıyor_mu, gerekçe). Sandbox / takılma sorunlarını erkenden yakalar."""
    profile = tempfile.mkdtemp(prefix="wss-browser-selftest-")
    try:
        if run_as:
            os.chown(profile, *run_as)
        args = [path] + ([] if _is_headless_shell(path) else ["--headless=new"]) + [
            "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--user-data-dir=" + profile]
        if no_sandbox:
            args.append("--no-sandbox")
        args += ["--dump-dom", "data:text/html,<p>wss-selftest</p>"]
        code, out, err, timed_out = _spawn(args, profile, run_as, 20)
        if timed_out:
            return False, ("Chromium başsız komutu 20 sn içinde bitmedi (bazı tam Chrome sürümlerinde --dump-dom "
                           "takılıyor); chrome-headless-shell kurun (Debian: chromium-headless-shell).")
        if b"wss-selftest" in (out or b""):
            return True, ""
        err_text = (err or b"").decode("utf-8", "replace")
        if _SANDBOX_ERR.search(err_text) and not no_sandbox:
            return False, ("Chromium sandbox başlatılamadı. Konteynerde gerekirse WSS_BROWSER_NO_SANDBOX=1 ile "
                           "sandbox'sız çalıştırmaya açıkça izin verebilirsiniz (risk: tarayıcı açığı konteyneri etkileyebilir).")
        last = [ln for ln in err_text.strip().splitlines() if ln.strip()][-1:] or ["?"]
        return False, "Chromium öz-testi başarısız (kod %s): %s" % (code, last[0][:200])
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def capabilities(refresh=False, local=False):
    """Arayüz / durum ucu için: Chromium var mı, sürümü, sandbox kipi (önbellekli)."""
    if not local and _service_url():
        return _remote_capabilities(refresh)
    with _CAPS_LOCK:
        if _CAPS_CACHE and not refresh:
            return dict(_CAPS_CACHE)
    path = find_chromium()
    caps = {"available": bool(path), "default_enabled": browser_enabled_default()}
    if path:
        caps.update({"binary": os.path.basename(path), "version": _chromium_version(path),
                     "mode": "headless-shell" if _is_headless_shell(path) else "headless=new",
                     "sandbox": "off (WSS_BROWSER_NO_SANDBOX=1)" if _no_sandbox_allowed() else "on"})
        run_as = _run_as_user()
        if os.name == "posix" and os.geteuid() == 0 and not run_as and not _no_sandbox_allowed():
            caps["available"] = False
            caps["reason"] = ("Süreç root ve uid 1000 kullanıcısı yok; Chromium sandbox'lı başlatılamaz "
                              "(sandbox'sız çalıştırmak için WSS_BROWSER_NO_SANDBOX=1 gerekir).")
        else:
            ok, reason = _self_test(path, run_as, _no_sandbox_allowed())
            caps["self_test"] = "ok" if ok else "failed"
            if not ok:
                caps["available"] = False
                caps["reason"] = reason
    else:
        caps["reason"] = ("Chromium bulunamadı. Docker: docker-compose.browser.yml ile kurun; yerel kurulum: "
                          "chromium paketini kurun ya da WSS_CHROMIUM_PATH ile yolunu verin.")
    with _CAPS_LOCK:
        _CAPS_CACHE.clear()
        _CAPS_CACHE.update(caps)
    return dict(caps)


# ---------------------------------------------------------------- kapsam kilitli vekil (proxy)
def _split_hostport(value, default_port):
    value = (value or "").strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port = value.rpartition(":")
        if not sep:
            host, port = value, ""
    try:
        port_num = int(port) if port else default_port
    except ValueError:
        return None, None
    return host.lower().rstrip("."), port_num


def _pipe(client, upstream):
    """CONNECT tüneli: iki soket arasında boşta kalana kadar çift yönlü aktarım."""
    sockets = [client, upstream]
    last = time.time()
    try:
        while time.time() - last < TUNNEL_IDLE_SECONDS:
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
            if errored:
                return
            for sock in readable:
                data = sock.recv(65536)
                if not data:
                    return
                (upstream if sock is client else client).sendall(data)
                last = time.time()
    except OSError:
        return


class _ScopeProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, scope_url, budget, allowed_methods):
        super().__init__(("127.0.0.1", 0), _ScopeProxyHandler)
        self.scope_url = scope_url
        self.scope_origin = normalize_origin(scope_url)
        self.budget = int(budget)
        self.allowed_methods = frozenset(m.upper() for m in allowed_methods)
        self.lock = threading.Lock()
        self.last_upstream = 0.0
        self.stats = {"requests": 0, "blocked_scope": 0, "blocked_method": 0, "blocked_budget": 0,
                      "upstream_errors": 0, "blocked_origins": []}

    def take_budget(self):
        with self.lock:
            if self.stats["requests"] >= self.budget:
                self.stats["blocked_budget"] += 1
                return False
            self.stats["requests"] += 1
            wait = self.last_upstream + PACE_SECONDS - time.time()
            if wait > 0:
                time.sleep(wait)
            self.last_upstream = time.time()
            return True

    def record_block(self, kind, origin=""):
        with self.lock:
            if kind != "blocked_budget":
                self.stats[kind] = self.stats.get(kind, 0) + 1
            samples = self.stats["blocked_origins"]
            if kind == "blocked_scope" and origin and origin not in samples and len(samples) < 10:
                samples.append(origin[:120])


class _ScopeProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WSS-ScopeProxy/1.0"
    rbufsize = 0  # ham soket: CONNECT sonrası tünel baytları okuma tamponuna kaçmasın

    def log_message(self, *args):
        pass

    def _deny(self, status, message, kind, origin=""):
        self.server.record_block(kind, origin)
        body = message.encode("utf-8")
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def do_CONNECT(self):
        host, port = _split_hostport(self.path, 443)
        origin = self.server.scope_origin
        if not host or not origin or origin[0] != "https" or (host, port) != (origin[1], origin[2]):
            return self._deny(403, "WSS kapsam vekili: kapsam dışı tünel engellendi.", "blocked_scope",
                              "%s:%s" % (host, port))
        if not self.server.take_budget():
            return self._deny(429, "WSS kapsam vekili: istek bütçesi doldu.", "blocked_budget")
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            return self._deny(502, "WSS kapsam vekili: hedefe bağlanılamadı.", "upstream_errors")
        try:
            self.send_response_only(200, "Connection Established")
            self.end_headers()
            _pipe(self.connection, upstream)
        finally:
            upstream.close()
            self.close_connection = True

    def _forward(self):
        target = self.path
        parts = urllib.parse.urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.netloc:
            return self._deny(400, "WSS kapsam vekili: mutlak http URL bekleniyor.", "blocked_scope")
        if not is_in_scope(target, self.server.scope_url):
            return self._deny(403, "WSS kapsam vekili: kapsam dışı istek engellendi.", "blocked_scope",
                              "%s://%s" % (parts.scheme.lower(), parts.netloc.lower()))
        if self.command.upper() not in self.server.allowed_methods:
            return self._deny(405, "WSS kapsam vekili: yalnızca salt-okunur yöntemlere izin verilir.",
                              "blocked_method")
        if not self.server.take_budget():
            return self._deny(429, "WSS kapsam vekili: istek bütçesi doldu.", "blocked_budget")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}
        headers["Connection"] = "close"
        body = None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            body = self.rfile.read(min(length, MAX_REQUEST_BODY))
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=20)
        try:
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(MAX_UPSTREAM_BODY)
            status, reason, resp_headers = resp.status, resp.reason, resp.getheaders()
        except Exception:
            return self._deny(502, "WSS kapsam vekili: hedef yanıt vermedi.", "upstream_errors")
        finally:
            conn.close()
        try:
            self.send_response_only(status, reason)
            for key, value in resp_headers:
                if key.lower() not in _HOP_BY_HOP and key.lower() != "content-length":
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command.upper() != "HEAD":
                self.wfile.write(data)
        except OSError:
            pass
        self.close_connection = True

    do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_PATCH = do_DELETE = _forward


class ScopedProxy:
    """Yalnızca kapsam kökenine izin veren, istek bütçeli yerel HTTP vekili (127.0.0.1, rastgele port)."""

    def __init__(self, scope_url, budget=DEFAULT_SESSION_BUDGET, allowed_methods=ALLOWED_HTTP_METHODS):
        self.server = _ScopeProxyServer(scope_url, budget, allowed_methods)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.2},
                                       name="wss-scope-proxy", daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def stats(self):
        with self.server.lock:
            out = dict(self.server.stats)
            out["blocked_origins"] = list(self.server.stats["blocked_origins"])
        return out


# ---------------------------------------------------------------- DOM'dan saldırı yüzeyi
class _SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts = [], [], []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button") and self._form is not None and a.get("name"):
            if a["name"] not in self._form["inputs"]:
                self._form["inputs"].append(a["name"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def extract_surface(dom, base_url, scope_url=None):
    """Çizilmiş DOM'dan kapsam içi bağlantılar ve formlar (JavaScript ile oluşanlar dahil)."""
    scope = scope_url or base_url
    parser = _SurfaceParser()
    try:
        parser.feed(dom or "")
        parser.close()
    except Exception:
        pass
    links = []
    for href in parser.links:
        h = href.strip()
        if not h or h.lower().startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        absolute = urllib.parse.urljoin(base_url, h).split("#", 1)[0]
        if is_in_scope(absolute, scope) and absolute not in links:
            links.append(absolute)
        if len(links) >= 100:
            break
    forms = []
    for f in parser.forms[:30]:
        action = urllib.parse.urljoin(base_url, f["action"] or base_url).split("#", 1)[0]
        if is_in_scope(action, scope):
            forms.append({"action": action, "method": f["method"] if f["method"] in ("get", "post") else "get",
                          "inputs": f["inputs"][:30]})
    return {"links": links, "forms": forms, "script_count": len(parser.scripts)}


# ---------------------------------------------------------------- tarayıcı oturumu
class BrowserSession:
    """Bir tarama boyunca tek kapsam vekili + geçici profiller; render() ve confirm_xss()."""

    def __init__(self, scope_url, budget=DEFAULT_SESSION_BUDGET):
        if not normalize_origin(scope_url):
            raise BrowserUnavailable("Geçersiz kapsam URL'si.")
        self.scope_url = scope_url
        self.budget = int(budget)
        self.chromium = find_chromium()
        self.no_sandbox = _no_sandbox_allowed()
        self.run_as = _run_as_user()
        self.proxy = None
        self.workdir = None
        self.renders = 0
        self.errors = []
        self._final_proxy_stats = {}

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def start(self):
        caps = capabilities(local=True)  # yerel oturum her zaman yerel Chromium'u denetler
        if not self.chromium or not caps.get("available"):
            raise BrowserUnavailable(caps.get("reason") or "Chromium bulunamadı.")
        if os.name == "posix" and os.geteuid() == 0 and not self.run_as and not self.no_sandbox:
            raise BrowserUnavailable("Süreç root ve uid 1000 kullanıcısı yok; Chromium sandbox'lı başlatılamaz.")
        self.workdir = tempfile.mkdtemp(prefix="wss-browser-")
        if self.run_as:
            os.chown(self.workdir, *self.run_as)
        self.proxy = ScopedProxy(self.scope_url, self.budget).start()

    def close(self):
        if self.proxy:
            self._final_proxy_stats = self.proxy.stats()
            self.proxy.stop()
            self.proxy = None
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    def _launch(self, args, profile):
        return _spawn(args, profile, self.run_as, RENDER_TIMEOUT_SECONDS)

    def render(self, url, screenshot=False):
        """URL'yi gerçek tarayıcıda çizer: {"ok", "dom", "screenshot"(base64 PNG), "error", "duration_ms"}."""
        result = {"ok": False, "url": url, "dom": "", "screenshot": None, "error": None, "duration_ms": 0}
        if not self.proxy:
            result["error"] = "Tarayıcı oturumu başlatılmadı."
            return result
        if not is_in_scope(url, self.scope_url):
            result["error"] = "Kapsam dışı URL tarayıcıda açılmadı."
            return result
        t0 = time.time()
        profile = tempfile.mkdtemp(dir=self.workdir)
        if self.run_as:
            os.chown(profile, *self.run_as)
        png = os.path.join(profile, "shot.png")
        args = [self.chromium]
        if not _is_headless_shell(self.chromium):
            args.append("--headless=new")
        args += _COMMON_FLAGS + ["--proxy-server=http://127.0.0.1:%d" % self.proxy.port,
                                 "--user-data-dir=" + profile,
                                 "--virtual-time-budget=%d" % VIRTUAL_TIME_BUDGET_MS]
        if self.no_sandbox:
            args.append("--no-sandbox")
        args.append("--dump-dom")
        if screenshot:
            args.append("--screenshot=" + png)
        args.append(url)
        code, out, err, timed_out = self._launch(args, profile)
        self.renders += 1
        err_text = (err or b"").decode("utf-8", "replace")
        dom = (out or b"")[:MAX_DOM_BYTES].decode("utf-8", "replace")
        if timed_out:
            result["error"] = "Tarayıcı %d sn içinde bitmedi." % RENDER_TIMEOUT_SECONDS
        elif code != 0 and not dom.strip():
            if _SANDBOX_ERR.search(err_text) and not self.no_sandbox:
                result["error"] = ("Chromium sandbox başlatılamadı. Konteynerde gerekirse WSS_BROWSER_NO_SANDBOX=1 ile "
                                   "sandbox'sız çalıştırmaya açıkça izin verebilirsiniz (risk: tarayıcı açığı "
                                   "konteyneri etkileyebilir).")
            else:
                last = [ln for ln in err_text.strip().splitlines() if ln.strip()][-1:] or ["?"]
                result["error"] = "Chromium hata verdi (kod %s): %s" % (code, last[0][:200])
        result["dom"] = dom
        result["ok"] = bool(dom.strip()) and not result["error"]
        if screenshot and os.path.isfile(png) and os.path.getsize(png) <= MAX_SCREENSHOT_BYTES:
            with open(png, "rb") as fh:
                result["screenshot"] = base64.b64encode(fh.read()).decode("ascii")
        shutil.rmtree(profile, ignore_errors=True)
        result["duration_ms"] = int((time.time() - t0) * 1000)
        if result["error"] and len(self.errors) < 5:
            self.errors.append(result["error"])
        return result

    def confirm_xss(self, url, param, screenshot=True):
        """param'a zararsız kanıt işaretini koyup sayfayı çizer; işaret ÇALIŞTIYSA executed=True."""
        nonce = secrets.token_hex(4)
        payload = XSS_PROOF_PAYLOAD.replace("NONCE", nonce)
        allowed, reason = validate_probe_payload(payload)
        if not allowed:
            return {"executed": False, "nonce": nonce, "error": "Kanıt işareti güvenlik kontrolünden geçmedi: " + reason}
        parts = urllib.parse.urlsplit(url)
        query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k != param]
        query.append((param, payload))
        probe = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                                         urllib.parse.urlencode(query), ""))
        res = self.render(probe, screenshot=screenshot)
        executed = bool(re.search(r"<html\b[^>]*\b%s=\"%s\"" % (XSS_PROOF_ATTR, nonce), res.get("dom") or "", re.I))
        return {"executed": executed, "nonce": nonce, "param": param, "probe_url": probe,
                "screenshot": res.get("screenshot") if executed else None,
                "error": res.get("error"), "duration_ms": res.get("duration_ms")}

    def stats(self):
        out = dict(self.proxy.stats() if self.proxy else self._final_proxy_stats)
        out.update({"renders": self.renders, "errors": list(self.errors),
                    "binary": os.path.basename(self.chromium or ""), "budget": self.budget,
                    "sandbox": "off" if self.no_sandbox else "on",
                    "run_as_uid": self.run_as[0] if self.run_as else None})
        return out


# ---------------------------------------------------------------- yalıtılmış yan konteyner (uzak servis)
REMOTE_CAPS_TTL = 60
_REMOTE_CACHE = {"at": 0.0, "caps": None}
_REFRESHING = threading.Event()
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _service_url():
    return os.environ.get("WSS_BROWSER_SERVICE_URL", "").strip().rstrip("/")


def _service_token():
    value = os.environ.get("WSS_BROWSER_SERVICE_TOKEN", "").strip()
    if value:
        return value
    path = os.environ.get("WSS_BROWSER_SERVICE_TOKEN_FILE", "").strip()
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""
    return ""


def _service_call(method, path, payload=None, timeout=30):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(_service_url() + path, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          "X-WSS-Browser-Token": _service_token()})
    try:
        with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        body.setdefault("ok", False)
        body.setdefault("error", "Tarayıcı servisi HTTP %d döndürdü." % e.code)
        return body
    except (OSError, ValueError) as e:
        return {"ok": False, "error": "Tarayıcı servisine ulaşılamadı: %s" % str(e)[:160]}


def _remote_capabilities(refresh=False):
    with _CAPS_LOCK:
        cached = _REMOTE_CACHE["caps"]
        if not refresh and cached is not None and time.time() - _REMOTE_CACHE["at"] < REMOTE_CAPS_TTL:
            return dict(cached)
    resp = _service_call("GET", "/capabilities", timeout=15)
    if resp.get("ok") and isinstance(resp.get("capabilities"), dict):
        caps = dict(resp["capabilities"])
    else:
        caps = {"available": False, "reason": resp.get("error") or "Tarayıcı servisi yanıt vermedi."}
    caps.update({"remote": True, "service": _service_url(), "default_enabled": browser_enabled_default()})
    with _CAPS_LOCK:
        _REMOTE_CACHE.update({"at": time.time(), "caps": dict(caps)})
    return caps


def capabilities_nonblocking():
    """Durum ucu için: önbellekteki değeri hemen döndürür, eskiyse arka planda yeniler (asla beklemez)."""
    with _CAPS_LOCK:
        if _service_url():
            cached = dict(_REMOTE_CACHE["caps"]) if _REMOTE_CACHE["caps"] is not None else None
            fresh = cached is not None and time.time() - _REMOTE_CACHE["at"] < REMOTE_CAPS_TTL
        else:
            cached = dict(_CAPS_CACHE) if _CAPS_CACHE else None
            fresh = cached is not None
    if not fresh and not _REFRESHING.is_set():
        _REFRESHING.set()

        def _refresh():
            try:
                capabilities(refresh=True)
            finally:
                _REFRESHING.clear()
        threading.Thread(target=_refresh, name="wss-browser-caps", daemon=True).start()
    if cached is None:
        return {"available": False, "checking": True, "reason": "Tarayıcı durumu kontrol ediliyor…"}
    return cached


class RemoteBrowserSession:
    """BrowserSession ile aynı arayüz; çizimi yalıtılmış wss-browser yan konteynerine yaptırır."""

    def __init__(self, scope_url, budget=DEFAULT_SESSION_BUDGET):
        if not normalize_origin(scope_url):
            raise BrowserUnavailable("Geçersiz kapsam URL'si.")
        self.scope_url = scope_url
        self.budget = int(budget)
        self.renders = 0
        self.errors = []
        self._remote = {}
        self._agg = {"requests": 0, "blocked_scope": 0, "blocked_method": 0, "blocked_budget": 0,
                     "upstream_errors": 0, "blocked_origins": []}

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def start(self):
        caps = capabilities(refresh=True)
        if not caps.get("available"):
            raise BrowserUnavailable(caps.get("reason") or "Tarayıcı servisi kullanılamıyor.")

    def close(self):
        pass

    def _call(self, path, payload):
        remaining = self.budget - self._agg["requests"]
        if remaining <= 0:
            return {"ok": False, "error": "Tarayıcı istek bütçesi doldu."}
        body = dict(payload, scope_url=self.scope_url, budget=remaining)
        resp = _service_call("POST", path, body, timeout=RENDER_TIMEOUT_SECONDS + 60)
        self.renders += 1
        stats = resp.get("stats") if isinstance(resp.get("stats"), dict) else {}
        for key in ("requests", "blocked_scope", "blocked_method", "blocked_budget", "upstream_errors"):
            self._agg[key] += int(stats.get(key) or 0)
        for origin in stats.get("blocked_origins") or []:
            if origin not in self._agg["blocked_origins"] and len(self._agg["blocked_origins"]) < 10:
                self._agg["blocked_origins"].append(origin)
        if stats:
            self._remote = stats
        if not resp.get("ok"):
            err = resp.get("error") or "Tarayıcı servisi hata verdi."
            if len(self.errors) < 5:
                self.errors.append(err)
            return {"ok": False, "error": err}
        result = resp.get("result")
        return result if isinstance(result, dict) else {}

    def render(self, url, screenshot=False):
        out = {"ok": False, "url": url, "dom": "", "screenshot": None, "error": None, "duration_ms": 0}
        out.update(self._call("/render", {"url": url, "screenshot": bool(screenshot)}))
        return out

    def confirm_xss(self, url, param, screenshot=True):
        out = {"executed": False, "nonce": None, "param": param, "screenshot": None, "error": None}
        out.update(self._call("/confirm_xss", {"url": url, "param": param, "screenshot": bool(screenshot)}))
        return out

    def stats(self):
        out = dict(self._agg)
        out["blocked_origins"] = list(self._agg["blocked_origins"])
        out.update({"renders": self.renders, "errors": list(self.errors), "budget": self.budget, "remote": True,
                    "binary": self._remote.get("binary", ""), "sandbox": self._remote.get("sandbox", "?")})
        return out


def open_session(scope_url, budget=DEFAULT_SESSION_BUDGET):
    """WSS_BROWSER_SERVICE_URL varsa yalıtılmış yan konteyneri, yoksa yerel Chromium'u kullanır."""
    if _service_url():
        return RemoteBrowserSession(scope_url, budget)
    return BrowserSession(scope_url, budget)
