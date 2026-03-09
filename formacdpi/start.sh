#!/bin/bash
# ══════════════════════════════════════════════
# ForMacDPI — Hızlı Başlatma Scripti
# ══════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/formacdpi.py"
PID_FILE="/tmp/formacdpi.pid"

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Python3 kontrolü
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Hata: python3 bulunamadı!${NC}"
    echo "Homebrew ile kurabilirsiniz: brew install python3"
    echo "Veya: xcode-select --install"
    exit 1
fi

# Python versiyonu kontrolü
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]); then
    echo -e "${RED}Hata: Python 3.8+ gerekli (mevcut: $PY_VER)${NC}"
    exit 1
fi

# Zaten çalışıyor mu kontrol et
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo -e "${YELLOW}ForMacDPI zaten çalışıyor (PID: $OLD_PID)${NC}"
        echo "Durdurmak için: $SCRIPT_DIR/stop.sh"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Uyarı: Sistem proxy otomatik ayarı için sudo gerekli${NC}"
    echo "sudo ile çalıştırmanız önerilir."
    echo ""
    echo "Devam etmek istiyor musunuz? (y/n)"
    read -r answer
    if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        echo "İptal edildi."
        exit 0
    fi
    SUDO_FLAG="--no-auto-proxy"
else
    SUDO_FLAG=""
fi

# Argümanları ilet (varsayılan: Türkiye modu + verbose)
ARGS="${@:--6 --verbose}"

echo -e "${GREEN}ForMacDPI başlatılıyor...${NC}"

# Python scripti başlat
python3 "$PYTHON_SCRIPT" $SUDO_FLAG $ARGS &
BGPID=$!
echo "$BGPID" > "$PID_FILE"

# Temizleme trap'i
cleanup() {
    echo ""
    echo -e "${YELLOW}Durduruluyor...${NC}"
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
}
trap cleanup EXIT INT TERM

# Arka plan sürecini bekle
wait $BGPID 2>/dev/null || true
rm -f "$PID_FILE"
