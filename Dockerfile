FROM python:3.12-slim

WORKDIR /app

# Opsiyonel bağımlılıklar (Vertex AI Service Account JWT vb.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Strix CLI (yalnızca INSTALL_STRIX=1 ile inşa edildiğinde; çekirdek sıfır-bağımlılık kalır)
ARG INSTALL_STRIX=0
RUN if [ "$INSTALL_STRIX" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/* && \
        pip install --no-cache-dir strix-agent; \
    fi

# Güvenlik ve çalıştırma ortamı değişkenleri
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8765 \
    NO_BROWSER=1

# Uygulama kaynak kodları ve statik dosyalar
COPY . .

# Root olmayan güvenli kullanıcı oluşturma
RUN useradd -m -u 1000 scanneruser && chown -R scanneruser:scanneruser /app
USER scanneruser

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/status')" || exit 1

CMD ["python3", "server.py"]
