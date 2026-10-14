#!/usr/bin/env bash
# =============================================================
# Web Security Scanner — İki Kademeli Tek Komut Kurulum (Lite vs Full)
#
# 1) ⚡ HIZLI KURULUM (Web Security Scanner Lite — Sıfır Bağımlılık, LLM Gerektirmez):
#    curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --lite
#
# 2) 🚀 KAPSAMLI KURULUM (Web Security Scanner Full — AI Red Team + Strix Sandbox):
#    curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --full
#
# 3) 🐳 DOCKER KURULUMU (Lite veya Full):
#    curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --docker-lite
#    curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --docker-full
# =============================================================
set -euo pipefail

REPO_URL="https://github.com/melihkarasu/web-security-scanner.git"
DEST="$HOME/web-security-scanner"
PORT="${PORT:-8765}"
EDITION=""
DOCKER_MODE=""

for arg in "$@"; do
  case "$arg" in
    --lite) EDITION="lite" ;;
    --full) EDITION="full" ;;
    --docker-lite) DOCKER_MODE="lite"; EDITION="lite" ;;
    --docker|--docker-full) DOCKER_MODE="full"; EDITION="full" ;;
    --help|-h)
      sed -n '2,15p' "$0" 2>/dev/null || true
      exit 0 ;;
  esac
done

say() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Etkileşimli terminalde bayrak verilmediyse kullanıcıya Lite vs Full sor
if [ -z "$EDITION" ] && [ -t 0 ]; then
  echo "============================================================="
  echo " 🛡️  Web Security Scanner — Kurulum Sürümü Seçimi"
  echo "============================================================="
  echo "  1) ⚡ Hızlı Kurulum (Lite Sürüm) [Varsayılan]"
  echo "     • Sıfır pip/Docker bağımlılığı, LLM/API anahtarı gerektirmez"
  echo "     • 7 Standart Analiz: Pasif Başlık, DNS, Derin Pasif, 98 Kural SAST,"
  echo "       8 Ekosistem CVE ve 12 Aktif Güvenlik Modülü (~2 sn içinde hazır)"
  echo ""
  echo "  2) 🚀 Kapsamlı Kurulum (Full Sürüm — AI Red Team & Strix Sandbox)"
  echo "     • Lite sürümdeki tüm özellikler + LLM/Service Account desteği"
  echo "     • AI Red Team + 4-Aşamalı AI SAST + Strix Docker Sandbox (~1.4 GB)"
  echo "============================================================="
  printf "Seçiminiz [1/2, varsayılan: 1]: "
  read -r choice || choice="1"
  if [ "$choice" = "2" ]; then
    EDITION="full"
  else
    EDITION="lite"
  fi
fi

EDITION="${EDITION:-lite}"

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
if [ -n "$DOCKER_MODE" ]; then
  command -v docker >/dev/null 2>&1 || die "docker bulunamadı."
  if [ "$DOCKER_MODE" = "lite" ]; then
    say "Docker Hızlı Kurulum (Lite — sıfır ek bağımlılık, non-root) başlatılıyor…"
    WSS_EDITION=lite docker compose -f "$DEST/docker-compose.yml" up -d --build
    say "Hazır: http://localhost:8765 (Web Security Scanner Lite — Docker)"
  else
    say "Docker Kapsamlı Kurulum (Full — AI Red Team + Strix Sandbox) başlatılıyor…"
    WSS_EDITION=full docker compose -f "$DEST/docker-compose.yml" -f "$DEST/docker-compose.strix.yml" up -d --build
    say "Hazır: http://localhost:8765 (Web Security Scanner Full — Docker)"
  fi
  exit 0
fi

# --- 3) Kapsamlı Kurulum (--full): cryptography + Strix CLI + Sandbox imajı ---
if [ "$EDITION" = "full" ]; then
  say "Kapsamlı Kurulum (Full) bileşenleri kontrol ediliyor…"
  python3 -m pip install --user -r "$DEST/requirements.txt" >/dev/null 2>&1 || true
  if command -v strix >/dev/null 2>&1; then
    say "Strix zaten kurulu: $(strix --version 2>/dev/null || echo '?')"
  elif command -v pipx >/dev/null 2>&1; then
    say "Strix pipx ile kuruluyor…"
    pipx install strix-agent || warn "pipx kurulumu başarısız; elle: pip install strix-agent"
  else
    say "Strix pip --user ile kuruluyor…"
    python3 -m pip install --user strix-agent || warn "Strix kurulumu başarısız; elle: pip install strix-agent"
  fi
  if command -v docker >/dev/null 2>&1; then
    say "Strix sandbox imajı çekiliyor (bir kez, ~1.4 GB)…"
    docker pull ghcr.io/usestrix/strix-sandbox:1.3.0 || warn "Sandbox imajı çekilemedi; Strix taramaları Docker gerektirir."
  else
    warn "Docker bulunamadı; AI Red Team ve 4-Aşamalı AI SAST çalışır, Strix sandbox için Docker gerekir."
  fi
else
  say "Hızlı Kurulum (Lite Sürüm) seçildi — sıfır ek paket, LLM yapılandırması gerektirmez."
fi

# --- 4) Sunucu ---
cd "$DEST"
export WSS_EDITION="$EDITION"
say "Sunucu başlatılıyor ($EDITION sürüm) → http://127.0.0.1:${PORT}"
say "Durdurmak için: Ctrl+C"
exec python3 server.py "--${EDITION}"
