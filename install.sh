#!/usr/bin/env bash
# =============================================================
# Web Security Scanner — Tek Komut, Seçmeli Bileşen Kurulumu
#
# Sürümler:
#   --lite   ⚡ Sıfır bağımlılık, LLM gerektirmez (pasif + aktif güvenlik modülleri)
#   --full   🚀 Lite'ın tümü + AI Red Team + 4-Aşamalı AI SAST (LLM/Service Account)
#
# Docker eklentileri (yalnızca --docker ile; seçmeli, birlikte kullanılabilir):
#   --with-browser   🖥️  Gerçek tarayıcı (yalıtılmış headless-Chromium yan konteyneri, ~570 MB)
#   --with-strix     🧪 Strix otonom sandbox (host Docker soketi, root; ~6 GB imaj)
#   --with-strix-dind 🔒 Strix YALITILMIŞ Docker'da (TLS dind; host soketi yok, non-root) — --with-strix yerine
#
# Örnekler (tek komut):
#   # Yerel Lite:
#   curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --lite
#   # Yerel Full (AI Red Team):
#   curl -fsSL .../install.sh | bash -s -- --full
#   # Docker Full + gerçek tarayıcı + izole Strix (hepsi seçmeli):
#   curl -fsSL .../install.sh | bash -s -- --docker --full --with-browser --with-strix-dind
#   # Bayrak vermeden çalıştırırsanız etkileşimli menü çıkar.
# =============================================================
set -euo pipefail

REPO_URL="https://github.com/melihkarasu/web-security-scanner.git"
DEST="\${WSS_DEST:-$HOME/web-security-scanner}"
PORT="\${PORT:-8765}"
EDITION=""
USE_DOCKER=""
WITH_BROWSER=""
WITH_STRIX=""
WITH_STRIX_DIND=""

for arg in "$@"; do
  case "$arg" in
    --lite) EDITION="lite" ;;
    --full) EDITION="full" ;;
    --docker) USE_DOCKER="1" ;;
    --docker-lite) USE_DOCKER="1"; EDITION="lite" ;;
    --docker-full) USE_DOCKER="1"; EDITION="full" ;;
    --with-browser|--browser) WITH_BROWSER="1" ;;
    --with-strix|--strix) WITH_STRIX="1" ;;
    --with-strix-dind|--strix-dind) WITH_STRIX_DIND="1" ;;
    --help|-h) sed -n '2,33p' "$0" 2>/dev/null || true; exit 0 ;;
    *) printf 'Bilinmeyen seçenek: %s (--help ile yardım)\n' "$arg" >&2 ;;
  esac
done

say() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Etkileşimli menü (bayrak verilmediyse ve terminal varsa) ---
if [ -z "$EDITION" ] && [ -z "$USE_DOCKER" ] && [ -t 0 ]; then
  echo "============================================================="
  echo " 🛡️  Web Security Scanner — Kurulum"
  echo "============================================================="
  echo "  Çalıştırma biçimi:"
  echo "   1) ⚡ Yerel — Lite (sıfır bağımlılık, LLM gerektirmez) [Varsayılan]"
  echo "   2) 🚀 Yerel — Full (AI Red Team + 4-Aşamalı AI SAST)"
  echo "   3) 🐳 Docker (bileşenleri aşağıda seçersiniz)"
  echo "============================================================="
  printf "Seçiminiz [1/2/3, varsayılan: 1]: "
  read -r choice || choice="1"
  case "$choice" in
    2) EDITION="full" ;;
    3) USE_DOCKER="1" ;;
    *) EDITION="lite" ;;
  esac
  if [ -n "$USE_DOCKER" ]; then
    echo ""
    echo "  Docker sürümü:"
    echo "   1) ⚡ Lite [Varsayılan]    2) 🚀 Full (AI Red Team)"
    printf "Seçiminiz [1/2, varsayılan: 1]: "
    read -r de || de="1"
    [ "$de" = "2" ] && EDITION="full" || EDITION="lite"
    echo ""
    echo "  Seçmeli eklentiler (y/N):"
    printf "   🖥️  Gerçek tarayıcı (izole headless-Chromium, ~570 MB)? [y/N]: "
    read -r b || b="n"; case "$b" in [yYeE]*) WITH_BROWSER="1" ;; esac
    printf "   🧪 Strix otonom sandbox? [y/N]: "
    read -r s || s="n"
    if case "$s" in [yYeE]*) true ;; *) false ;; esac; then
      printf "      🔒 İzole Docker'da mı çalışsın (dind; daha güvenli, non-root, host soketi yok)? [Y/n]: "
      read -r d || d="y"
      case "$d" in [nN]*) WITH_STRIX="1" ;; *) WITH_STRIX_DIND="1" ;; esac
    fi
  fi
fi

EDITION="\${EDITION:-lite}"
# --with-strix-dind, --with-strix'in yerine geçer (ikisi birden seçilemez)
if [ -n "$WITH_STRIX_DIND" ]; then WITH_STRIX=""; fi
# Strix yalnızca Full ile anlamlı (AI gerektirir); Docker'da Strix seçildiyse sürümü Full'e yükselt
if { [ -n "$WITH_STRIX" ] || [ -n "$WITH_STRIX_DIND" ]; } && [ "$EDITION" != "full" ]; then
  warn "Strix AI gerektirir; sürüm otomatik olarak Full'e yükseltildi."
  EDITION="full"
fi

command -v python3 >/dev/null 2>&1 || die "python3 bulunamadı. https://python.org adresinden kurun."

# --- 1) Depo ---
if [ -d "$DEST/.git" ]; then
  say "Mevcut kurulum güncelleniyor: $DEST"
  git -C "$DEST" pull --ff-only || warn "git pull başarısız; mevcut sürümle devam ediliyor."
else
  say "Depo klonlanıyor: $DEST"
  git clone --depth 1 "$REPO_URL" "$DEST"
fi
cd "$DEST"

# --- 2) Docker modu: seçili bileşenlerden COMPOSE_FILE zinciri kurulur ---
if [ -n "$USE_DOCKER" ]; then
  command -v docker >/dev/null 2>&1 || die "docker bulunamadı."
  docker compose version >/dev/null 2>&1 || die "docker compose (v2) bulunamadı."

  FILES="docker-compose.yml"
  COMPONENTS="Çekirdek (Web Security Scanner $EDITION)"
  if [ -n "$WITH_BROWSER" ]; then
    FILES="$FILES:docker-compose.browser.yml"; COMPONENTS="$COMPONENTS + Gerçek Tarayıcı"
  fi
  if [ -n "$WITH_STRIX_DIND" ]; then
    FILES="$FILES:docker-compose.strix-dind.yml"; COMPONENTS="$COMPONENTS + Strix (izole dind)"
  elif [ -n "$WITH_STRIX" ]; then
    FILES="$FILES:docker-compose.strix.yml"; COMPONENTS="$COMPONENTS + Strix (host soketi)"
  fi

  # Seçimi .env'e yaz: sonraki 'docker compose up -d' aynı bileşenleri kullanır (kalıcı).
  {
    echo "# Web Security Scanner — seçili Docker bileşenleri (install.sh tarafından yazıldı)."
    echo "# Varsayılana dönmek için bu dosyayı silin. (.gitignore kapsamındadır.)"
    echo "COMPOSE_FILE=$FILES"
    echo "WSS_EDITION=$EDITION"
  } > .env

  say "Docker kurulumu: $COMPONENTS"
  say "Compose dosyaları: $FILES"
  # shellcheck disable=SC2086
  WSS_EDITION="$EDITION" docker compose up -d --build

  if [ -n "$WITH_STRIX_DIND" ]; then
    warn "İzole Strix (dind): sandbox imajını bir kez izole depoya çekin (~6 GB):"
    warn "  docker compose exec web-security-scanner docker pull ghcr.io/usestrix/strix-sandbox:1.3.0"
  elif [ -n "$WITH_STRIX" ]; then
    say "Strix sandbox imajı çekiliyor (bir kez, ~6 GB)…"
    docker pull ghcr.io/usestrix/strix-sandbox:1.3.0 || warn "Sandbox imajı çekilemedi; Strix taramaları için gerekli."
  fi
  echo ""
  say "Hazır: http://localhost:$PORT  ($COMPONENTS)"
  say "Durum/yönetim: docker compose ps   ·   Durdurma: docker compose down"
  exit 0
fi

# --- 3) Yerel Full: cryptography + Strix CLI (Docker'sız yerel kurulumda Strix opsiyoneldir) ---
if [ "$EDITION" = "full" ]; then
  say "Full bileşenleri hazırlanıyor (cryptography vb.)…"
  python3 -m pip install --user -r "$DEST/requirements.txt" >/dev/null 2>&1 || warn "pip bağımlılıkları kurulamadı; AI özellikleri sınırlı olabilir."
  if [ -n "$WITH_STRIX" ] || [ -n "$WITH_STRIX_DIND" ]; then
    if command -v strix >/dev/null 2>&1; then
      say "Strix zaten kurulu: $(strix --version 2>/dev/null || echo '?')"
    elif command -v pipx >/dev/null 2>&1; then
      say "Strix pipx ile kuruluyor…"; pipx install strix-agent || warn "pipx kurulumu başarısız; elle: pipx install strix-agent"
    else
      say "Strix pip --user ile kuruluyor…"; python3 -m pip install --user strix-agent || warn "Strix kurulumu başarısız; elle: pip install strix-agent"
    fi
    if command -v docker >/dev/null 2>&1; then
      say "Strix sandbox imajı çekiliyor (bir kez, ~6 GB)…"
      docker pull ghcr.io/usestrix/strix-sandbox:1.3.0 || warn "Sandbox imajı çekilemedi; Strix taramaları Docker gerektirir."
    else
      warn "Docker yok; AI Red Team ve AI SAST çalışır, Strix sandbox için Docker gerekir."
    fi
  fi
else
  say "Lite sürüm — sıfır ek paket, LLM yapılandırması gerektirmez."
fi

# --- 4) Sunucu ---
export WSS_EDITION="$EDITION"
say "Sunucu başlatılıyor ($EDITION) → http://127.0.0.1:$PORT   (durdurmak için Ctrl+C)"
exec python3 server.py "--$EDITION"
