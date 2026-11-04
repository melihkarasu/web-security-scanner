#!/usr/bin/env bash
# =============================================================
# Web Security Scanner — Tek Komut, Seçmeli Bileşen Kurulumu
#
# Sürümler:
#   --lite          ⚡ Sıfır bağımlılık, LLM gerektirmez (pasif + aktif güvenlik modülleri)
#   --full          🚀 Lite'ın tümü + AI Red Team + 4-Aşamalı AI SAST + Gerçek Tarayıcı (Chromium) + Strix CLI
#   --docker-lite   🐳 Docker Lite (hafif imaj, sıfır ek bağımlılık, non-root)
#   --docker-full   🐳 Docker Full (AI Red Team + Headless Chromium + Strix CLI & Sandbox hazır gelir)
#
# Seçmeli Docker bileşen bayrakları (--docker ile birlikte veya özelleştirme için):
#   --with-browser     🖥️  Gerçek tarayıcı (yalıtılmış headless-Chromium yan konteyneri)
#   --no-browser       🚫 Full kurulumda gerçek tarayıcıyı devre dışı bırak
#   --with-strix       🧪 Strix otonom AI pentest (host Docker soketi üzerinden sandbox)
#   --with-strix-dind  🔒 Strix otonom AI pentest (izole TLS docker:dind üzerinde; host soketi bağlanmaz)
#   --no-strix         🚫 Full kurulumda Strix'i devre dışı bırak
#
# Örnekler:
#   # Yerel Lite (varsayılan, en hızlı):
#   curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --lite
#   # Yerel Full (AI Red Team + Strix CLI + Chromium kontrolü):
#   curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --full
#   # Docker Full (Chromium + Strix hazır gelir):
#   curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --docker-full
#   # Docker Full + İzole Strix (dind):
#   curl -fsSL https://raw.githubusercontent.com/melihkarasu/web-security-scanner/main/install.sh | bash -s -- --docker-full --with-strix-dind
#   # Bayrak vermeden çalıştırırsanız etkileşimli menü çıkar.
# =============================================================
set -euo pipefail

REPO_URL="https://github.com/melihkarasu/web-security-scanner.git"
DEST="${WSS_DEST:-$HOME/web-security-scanner}"
PORT="${PORT:-8765}"
EDITION=""
USE_DOCKER=""
WITH_BROWSER=""
NO_BROWSER_COMP=""
WITH_STRIX=""
WITH_STRIX_DIND=""
NO_STRIX_COMP=""

for arg in "$@"; do
  case "$arg" in
    --lite) EDITION="lite" ;;
    --full) EDITION="full" ;;
    --docker) USE_DOCKER="1" ;;
    --docker-lite) USE_DOCKER="1"; EDITION="lite" ;;
    --docker-full) USE_DOCKER="1"; EDITION="full" ;;
    --with-browser|--browser) WITH_BROWSER="1"; NO_BROWSER_COMP="" ;;
    --no-browser|--without-browser) NO_BROWSER_COMP="1"; WITH_BROWSER="" ;;
    --with-strix|--strix) WITH_STRIX="1"; NO_STRIX_COMP="" ;;
    --with-strix-dind|--strix-dind) WITH_STRIX_DIND="1"; NO_STRIX_COMP="" ;;
    --no-strix|--without-strix) NO_STRIX_COMP="1"; WITH_STRIX=""; WITH_STRIX_DIND="" ;;
    -h|--help)
      sed -n '2,28p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
  esac
done

say()  { printf "\033[1;36m[WebSecurityScanner]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WebSecurityScanner]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[WebSecurityScanner HATA]\033[0m %s\n" "$*" >&2; exit 1; }

# curl | bash ile çalıştırıldığında etkileşimli girdiyi /dev/tty'den oku
prompt_read() {
  local __var="$1" __default="${2:-}" __val=""
  if [ -t 0 ]; then
    read -r __val || __val="$__default"
  elif [ -e /dev/tty ] && [ -r /dev/tty ]; then
    read -r __val < /dev/tty || __val="$__default"
  else
    __val="$__default"
  fi
  [ -z "$__val" ] && __val="$__default"
  printf -v "$__var" '%s' "$__val"
}

# --- Etkileşimli menü (hiçbir bayrak verilmediyse) ---
if [ -z "$EDITION" ] && [ -z "$USE_DOCKER" ] && [ -z "$WITH_BROWSER" ] && [ -z "$WITH_STRIX" ] && [ -z "$WITH_STRIX_DIND" ]; then
  echo ""
  echo "============================================================="
  echo "  🛡️  Web Security Scanner — Kurulum Modu Seçin"
  echo "============================================================="
  echo "   1) ⚡ Yerel — Lite (sıfır bağımlılık, LLM gerektirmez) [Varsayılan]"
  echo "   2) 🚀 Yerel — Full (AI Red Team + 4-Aşamalı AI SAST + Strix CLI)"
  echo "   3) 🐳 Docker (Lite veya Full — Full'de Strix ve Chromium hazır gelir)"
  echo "============================================================="
  printf "Seçiminiz [1/2/3, varsayılan: 1]: "
  prompt_read choice "1"
  case "$choice" in
    2) EDITION="full" ;;
    3) USE_DOCKER="1" ;;
    *) EDITION="lite" ;;
  esac
  if [ -n "$USE_DOCKER" ]; then
    echo ""
    echo "  Docker sürümü:"
    echo "   1) ⚡ Lite (Hafif, sıfır ek paket)"
    echo "   2) 🚀 Full (AI Red Team + Gerçek Tarayıcı Chromium + Strix Sandbox) [Varsayılan]"
    printf "Seçiminiz [1/2, varsayılan: 2]: "
    prompt_read de "2"
    [ "$de" = "1" ] && EDITION="lite" || EDITION="full"
    echo ""
    if [ "$EDITION" = "full" ]; then
      echo "  Full sürüm bileşenleri (varsayılan olarak DAHİL):"
      printf "   🖥️  Gerçek tarayıcı (headless Chromium)? [Y/n]: "
      prompt_read b "y"
      case "$b" in [nN]*) NO_BROWSER_COMP="1" ;; *) WITH_BROWSER="1" ;; esac
      printf "   🧪 Strix otonom AI pentest & sandbox? [Y/n]: "
      prompt_read s "y"
      if case "$s" in [nN]*) false ;; *) true ;; esac; then
        printf "      🔒 Strix çalışma kipi: [1] Host Docker soketi (varsayılan, hızlı) / [2] İzole Docker (dind) [1/2]: "
        prompt_read d "1"
        case "$d" in 2|[dD]*) WITH_STRIX_DIND="1" ;; *) WITH_STRIX="1" ;; esac
      else
        NO_STRIX_COMP="1"
      fi
    else
      echo "  Seçmeli eklentiler (y/N):"
      printf "   🖥️  Gerçek tarayıcı (izole headless-Chromium, ~570 MB)? [y/N]: "
      prompt_read b "n"
      case "$b" in [yYeE]*) WITH_BROWSER="1" ;; esac
      printf "   🧪 Strix otonom sandbox? [y/N]: "
      prompt_read s "n"
      if case "$s" in [yYeE]*) true ;; *) false ;; esac; then
        printf "      🔒 İzole Docker'da mı çalışsın (dind; daha güvenli, non-root, host soketi yok)? [Y/n]: "
        prompt_read d "y"
        case "$d" in [nN]*) WITH_STRIX="1" ;; *) WITH_STRIX_DIND="1" ;; esac
      fi
    fi
  fi
fi

EDITION="${EDITION:-lite}"
# Strix yalnızca Full ile anlamlı (AI gerektirir); Strix seçildiyse sürümü Full'e yükselt
if { [ -n "$WITH_STRIX" ] || [ -n "$WITH_STRIX_DIND" ]; } && [ "$EDITION" != "full" ]; then
  warn "Strix AI gerektirir; sürüm otomatik olarak Full'e yükseltildi."
  EDITION="full"
fi

# Full sürüm seçildiğinde (--full, --docker-full veya "--docker --full")
# kullanıcı açıkça --no-browser / --no-strix vermediyse Chromium ve Strix varsayılan olarak DAHİL edilir!
if [ "$EDITION" = "full" ]; then
  if [ -z "$NO_BROWSER_COMP" ] && [ -z "$WITH_BROWSER" ]; then
    WITH_BROWSER="1"
  fi
  if [ -z "$NO_STRIX_COMP" ] && [ -z "$WITH_STRIX" ] && [ -z "$WITH_STRIX_DIND" ]; then
    WITH_STRIX="1"
  fi
fi

# --with-strix-dind, --with-strix'in yerine geçer (ikisi birden seçilemez)
if [ -n "$WITH_STRIX_DIND" ]; then WITH_STRIX=""; fi

command -v git >/dev/null 2>&1 || die "git bulunamadı. Lütfen git kurun."
if [ -z "$USE_DOCKER" ]; then
  command -v python3 >/dev/null 2>&1 || die "python3 bulunamadı. https://www.python.org/downloads/ adresinden kurun."
fi

# --- 1) Depo ---
if [ -d "$DEST/.git" ]; then
  say "Mevcut kurulum güncelleniyor: $DEST"
  git -C "$DEST" pull --ff-only || warn "git pull atlandı, mevcut dosyalarla devam ediliyor."
else
  say "Depo indiriliyor → $DEST"
  git clone --depth 1 "$REPO_URL" "$DEST"
fi
cd "$DEST"

# --- 2) Docker kurulumu ---
if [ -n "$USE_DOCKER" ]; then
  command -v docker >/dev/null 2>&1 || die "docker bulunamadı. Docker Desktop veya docker.io kurun."

  FILES="docker-compose.yml"
  COMPONENTS="Çekirdek (Web Security Scanner $EDITION)"
  INSTALL_CHROMIUM_FLAG="0"
  INSTALL_STRIX_FLAG="0"

  if [ "$EDITION" = "full" ]; then
    INSTALL_CHROMIUM_FLAG="1"
    INSTALL_STRIX_FLAG="1"
  fi
  if [ -n "$WITH_BROWSER" ]; then
    INSTALL_CHROMIUM_FLAG="1"
    FILES="$FILES:docker-compose.browser.yml"
    COMPONENTS="$COMPONENTS + Gerçek Tarayıcı (Chromium)"
  fi
  if [ -n "$WITH_STRIX_DIND" ]; then
    INSTALL_STRIX_FLAG="1"
    FILES="$FILES:docker-compose.strix-dind.yml"
    COMPONENTS="$COMPONENTS + Strix (izole dind)"
  elif [ -n "$WITH_STRIX" ]; then
    INSTALL_STRIX_FLAG="1"
    FILES="$FILES:docker-compose.strix.yml"
    COMPONENTS="$COMPONENTS + Strix (host soketi)"
  fi
  if [ -n "$NO_BROWSER_COMP" ]; then
    INSTALL_CHROMIUM_FLAG="0"
  fi
  if [ -n "$NO_STRIX_COMP" ]; then
    INSTALL_STRIX_FLAG="0"
  fi

  # Seçimi .env'e yaz: sonraki 'docker compose up -d' aynı bileşenleri kullanır (kalıcı).
  {
    echo "# Web Security Scanner — seçili Docker bileşenleri (install.sh tarafından yazıldı)."
    echo "# Varsayılana dönmek için bu dosyayı silin. (.gitignore kapsamındadır.)"
    echo "COMPOSE_FILE=$FILES"
    echo "WSS_EDITION=$EDITION"
    echo "INSTALL_CHROMIUM=$INSTALL_CHROMIUM_FLAG"
    echo "INSTALL_STRIX=$INSTALL_STRIX_FLAG"
  } > .env

  say "Docker kurulumu: $COMPONENTS"
  say "Compose dosyaları: $FILES"
  WSS_EDITION="$EDITION" INSTALL_CHROMIUM="$INSTALL_CHROMIUM_FLAG" INSTALL_STRIX="$INSTALL_STRIX_FLAG" docker compose up -d --build

  if [ -n "$WITH_STRIX_DIND" ]; then
    say "İzole Strix (dind): sandbox imajı izole depoya çekiliyor (~6 GB, bir kez)…"
    docker compose exec web-security-scanner docker pull ghcr.io/usestrix/strix-sandbox:1.3.0 || warn "Sandbox imajı çekilemedi; daha sonra 'docker compose exec web-security-scanner docker pull ghcr.io/usestrix/strix-sandbox:1.3.0' çalıştırabilirsiniz."
  elif [ -n "$WITH_STRIX" ]; then
    say "Strix sandbox imajı çekiliyor (bir kez, ~6 GB)…"
    docker pull ghcr.io/usestrix/strix-sandbox:1.3.0 || warn "Sandbox imajı çekilemedi; Strix taramaları için gerekli."
  fi
  echo ""
  say "Hazır: http://localhost:$PORT  ($COMPONENTS)"
  say "Durum/yönetim: docker compose ps   ·   Durdurma: docker compose down"
  exit 0
fi

# --- 3) Yerel Full: cryptography + Strix CLI + Chromium kontrolü ---
if [ "$EDITION" = "full" ]; then
  say "Full bileşenleri hazırlanıyor (cryptography vb.)…"
  python3 -m pip install --user -r "$DEST/requirements.txt" >/dev/null 2>&1 || warn "pip bağımlılıkları kurulamadı; AI özellikleri sınırlı olabilir."
  if [ -n "$WITH_STRIX" ] || [ -n "$WITH_STRIX_DIND" ]; then
    if command -v strix >/dev/null 2>&1; then
      say "Strix zaten kurulu: $(command -v strix)"
    else
      say "Strix CLI (strix-agent) kuruluyor…"
      if command -v pipx >/dev/null 2>&1; then
        pipx install strix-agent || warn "pipx ile strix-agent kurulamadı."
      else
        python3 -m pip install --user strix-agent || warn "pip ile strix-agent kurulamadı."
      fi
    fi
    if command -v docker >/dev/null 2>&1; then
      say "Strix sandbox imajı çekiliyor (bir kez)…"
      docker pull ghcr.io/usestrix/strix-sandbox:1.3.0 || warn "Docker imajı çekilemedi."
    else
      warn "Docker bulunamadı — yerleşik 10 analiz modülü çalışır, Strix sandbox için Docker gerekir."
    fi
  fi
  if [ -n "$WITH_BROWSER" ]; then
    if command -v chromium-headless-shell >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
      say "Gerçek tarayıcı (Chromium/Chrome) bulundu."
    else
      warn "Yerel sistemde Chromium bulunamadı. Gerçek tarayıcı motoru için chromium/google-chrome kurun veya Docker Full (--docker-full) kullanın."
    fi
  fi
else
  say "Lite sürüm — sıfır ek paket, LLM yapılandırması gerektirmez."
fi

# --- 4) Sunucu ---
export WSS_EDITION="$EDITION"
say "Sunucu başlatılıyor ($EDITION) → http://127.0.0.1:$PORT   (durdurmak için Ctrl+C)"
exec python3 server.py "--$EDITION"
