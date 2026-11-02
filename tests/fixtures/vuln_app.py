"""Testler için bilinçli zayıf yerel uygulama (yalnızca 127.0.0.1, rastgele port).

Gizli değerler (oturum çerezi, AWS anahtarı, JWT) maskeleme testleri için sayfaya gömülüdür.
Her istek yolu server.request_log listesine yazılır (gönderilmemesi gereken istekleri doğrulamak için).
"""
import html
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET_SESSION = "SUPERSECRETSESSION123"
SECRET_AWS = "AKIAIOSFODNN7EXAMPLE"
SECRET_JWT_SIGNATURE = "c2lnbmF0dXJlLXRoYXQtbXVzdC1ub3QtbGVhaw"
SECRET_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
              "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9." + SECRET_JWT_SIGNATURE)


# Testlerin değiştirebildiği durum: XSS'i "düzelt" ve sürüm başlığı gönder (varsayılanlar eski davranış)
FIXTURE_STATE = {"escape_search": False, "powered_by": None}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.request_log.append(self.path)
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            body = ("<html><head><title>Fixture</title></head><body>"
                    "<!-- deploy key: %s -->"
                    "<script>window.__TOKEN__ = '%s';</script>"
                    "<form action='/search' method='get'><input name='q' value=''></form>"
                    "<a href='/item?id=1'>item</a> <a href='/redirect?to=/'>r</a>"
                    "</body></html>") % (SECRET_AWS, SECRET_JWT)
            self._send(200, body, cookie=True)
        elif parsed.path == "/search":
            q = qs.get("q", [""])[0]
            if FIXTURE_STATE["escape_search"]:
                q = html.escape(q)
            self._send(200, "<html><body>Results for: %s</body></html>" % q)
        elif parsed.path == "/item":
            item = qs.get("id", [""])[0]
            if "'" in item:
                self._send(500, "You have an error in your SQL syntax; check the manual near '%s'" % item)
            else:
                self._send(200, "<html><body>Item %s</body></html>" % item)
        elif parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", qs.get("to", ["/"])[0])
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif parsed.path == "/spa":
            # Bağlantı ve form JavaScript ile oluşur (statik HTML ayrıştırıcı göremez; gerçek tarayıcı görür)
            self._send(200, "<html><body><div id=app></div><script>"
                       "var a=document.createElement('a');a.href='/item?id=42';a.textContent='dyn';"
                       "document.getElementById('app').appendChild(a);"
                       "var f=document.createElement('form');f.action='/search';f.method='get';"
                       "var i=document.createElement('input');i.name='q';f.appendChild(i);"
                       "document.body.appendChild(f);</script></body></html>")
        elif parsed.path == "/embed":
            # Kapsam dışı alt kaynak testi: verilen adresten resim yüklemeye çalışan sayfa
            self._send(200, "<html><body><img src=\"%s\"></body></html>" % html.escape(qs.get("src", [""])[0], quote=True))
        elif parsed.path == "/account/delete":
            # Durum değiştiren uç (yalnızca kayıt tutar; ana sayfadan BAĞLANTI VERİLMEZ)
            self._send(200, "<html><body>deleted %s</body></html>" % qs.get("id", [""])[0])
        else:
            self._send(404, "not found")

    def _send(self, status, body, cookie=False):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if FIXTURE_STATE.get("powered_by"):
            self.send_header("X-Powered-By", FIXTURE_STATE["powered_by"])
        if cookie:
            self.send_header("Set-Cookie", "session=%s; Path=/; HttpOnly" % SECRET_SESSION)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_fixture_app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.request_log = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]
