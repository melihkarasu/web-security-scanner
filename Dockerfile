FROM python:3.12-slim

WORKDIR /app

# Opsiyonel bağımlılıklar (Vertex AI Service Account JWT vb.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Gerçek tarayıcı (headless Chromium) ve Strix CLI:
# Varsayılan olarak Full kurulumda (INSTALL_CHROMIUM=1, INSTALL_STRIX=1) imaj içinde hazır gelir.
# Lite kurulumda (--docker-lite) INSTALL_CHROMIUM=0 ve INSTALL_STRIX=0 ile hafif imaj üretilir.
# Not: Debian 13'te docker.io CLI barındırmaz; sandbox konteynerleri host/dind daemon'da
# çalıştığından yalnızca docker-cli yeterlidir.
ARG INSTALL_CHROMIUM=1
ARG INSTALL_STRIX=1
RUN if [ "$INSTALL_CHROMIUM" = "1" ] || [ "$INSTALL_STRIX" = "1" ]; then \
        apt-get update && \
        PKGS="" && \
        if [ "$INSTALL_CHROMIUM" = "1" ]; then PKGS="$PKGS chromium-headless-shell fonts-liberation"; fi && \
        if [ "$INSTALL_STRIX" = "1" ]; then PKGS="$PKGS docker-cli"; fi && \
        apt-get install -y --no-install-recommends $PKGS && \
        rm -rf /var/lib/apt/lists/*; \
    fi && \
    if [ "$INSTALL_STRIX" = "1" ]; then \
        pip install --no-cache-dir strix-agent; \
    fi

# Güvenlik ve çalıştırma ortamı değişkenleri
# Docker varsayılan seccomp profili unprivileged userns'i kısıtladığından konteyner içi Chromium için WSS_BROWSER_NO_SANDBOX=1 açık gelir
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8765 \
    NO_BROWSER=1 \
    WSS_BROWSER_NO_SANDBOX=1

# Uygulama kaynak kodları ve statik dosyalar
COPY . .

# Root olmayan güvenli kullanıcı oluşturma
RUN mkdir -p /app/data /app/strix_scans && useradd -m -u 1000 scanneruser && chown -R scanneruser:scanneruser /app
USER scanneruser

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz')" || exit 1

CMD ["python3", "server.py"]
