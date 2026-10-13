#!/usr/bin/env bash
# =============================================================
# Web Security Scanner — Tek Komut Kurulum (Linux / macOS)
# Kullanım:  curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash
#
# Yapılanlar:
#   1) Repoyu ~/web-security-scanner konumuna klonlar (varsa günceller)
#   2) python3 ile sunucuyu başlatır (sıfır pip bağımlılığı; cryptography opsiyonel)
#   3) --full bayrağı ile: Strix CLI + sandbox imajını da kurar
#      (AI Red Team + SAST çekirdeği Strix olmadan da tam çalışır)
#
# Seçenekler:
#   bash <(curl -fsSL ...) --full     → Strix dahil kurulum
#   bash <(curl -fsSL ...) --docker   → sadece Docker modu kurulumu
#   bash <(curl -fsSL ...) --help
# =============================================================
set -euo pipefail

REPO_URL="https://github.com/melihkarasu/web-security-scanner.git"
DEST="$HOME/web-security-scanner"
PORT="${PORT:-8765}"
FULL=0
DOCKER_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --full) FULL=1 ;;
    --docker) DOCKER_ONLY=1 ;;
    --help|-h)
      sed -n '2,16p' "$0" 2>/dev/null || true
      exit 0 ;;
  esac
done

say() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 bulunamadı. https://python.org adresinden kurun."

# --- 1) Depo ---
if [ -d "$DEST/.git" ]; then
  say "Mevcut kurulum güncelleniyor: $DEST"
  git -C "$DEST" pull --ff-only
else
  say "Depo klonlanıyor: $DEST"
  git clone --depth 1 "$REPO_URL" "$DEST"
fi

# --- 2) Docker modu ---
if [ "$DOCKER_ONLY" = "1" ]; then
  command -v docker >/dev/null 2>&1 || die "docker bulunamadı."
  say "Docker kurulumu başlatılıyor (web-security-scanner + Strix sandbox)…"
  docker compose -f "$DEST/docker-compose.yml" -f "$DEST/docker-compose.strix.yml" up -d --build
  say "Hazır: http://localhost:8765 (Docker, Strix dahil)"
  exit 0
fi

# --- 3) Strix (opsiyonel, --full) ---
if [ "$FULL" = "1" ]; then
  if command -v strix >/dev/null 2>&1; then
    say "Strix zaten kurulu: $(strix --version 2>/dev/null || echo '?')"
  elif command -v pipx >/dev/null 2>&1; then
    say "Strix pipx ile kuruluyor…"
    pipx install strix-agent || warn "pipx kurulumu başarısız; elle: pip install strix-agent"
  else
    say "Strix pip --user ile kuruluyor…"
    python3 -m pip install --user strix-agent || warn "Strix kurulumu başarısız; elle: pip install strix-agent"
  fi
  # Strix sandbox imajını da çek (Docker modunda taramalar için)
  if [ "$FULL" = "1" ]; then
    say "Strix sandbox imajı çekiliyor (bir kez, ~1.4 GB)…"
    docker pull ghcr.io/usestrix/strix-sandbox || warn "Sandbox imajı çekilemedi; Strix taramaları Docker gerektirir."
  fi
fi

# --- 4) Sunucu ---
cd "$DEST"
say "Sunucu başlatılıyor → http://127.0.0.1:${PORT}"
say "Durdurmak için: Ctrl+C"
if command -v python3 >/dev/null 2>&1; then
  exec python3 server.py
fi
