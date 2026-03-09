#!/bin/bash
# ══════════════════════════════════════════════
# ForMacDPI — Durdurma Scripti
# ══════════════════════════════════════════════

PID_FILE="/tmp/formacdpi.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}ForMacDPI durduruluyor...${NC}"

# PID dosyasından durdur
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        echo -e "${GREEN}Süreç durduruldu (PID: $PID)${NC}"
    else
        echo "Süreç zaten çalışmıyor."
    fi
    rm -f "$PID_FILE"
else
    # PID dosyası yoksa process'i bul
    PIDS=$(pgrep -f "formacdpi.py" 2>/dev/null)
    if [ -n "$PIDS" ]; then
        echo "$PIDS" | while read -r pid; do
            kill "$pid" 2>/dev/null && echo -e "${GREEN}Süreç durduruldu (PID: $pid)${NC}"
        done
    else
        echo "Çalışan ForMacDPI süreci bulunamadı."
    fi
fi

# Sistem proxy'sini temizle (güvenlik için)
if [ "$EUID" -eq 0 ]; then
    # Aktif ağ servisini bul
    INTERFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    if [ -n "$INTERFACE" ]; then
        SERVICE=$(networksetup -listallhardwareports | awk -v dev="$INTERFACE" '
            /Hardware Port:/{svc=$0; sub(/Hardware Port: /,"",svc)}
            /Device:/{if($2==dev) print svc}
        ')
        if [ -n "$SERVICE" ]; then
            networksetup -setwebproxystate "$SERVICE" off 2>/dev/null
            networksetup -setsecurewebproxystate "$SERVICE" off 2>/dev/null
            echo -e "${GREEN}Sistem proxy kapatıldı: $SERVICE${NC}"
        fi
    fi

    # Fallback: bilinen servisleri dene
    for svc in "Wi-Fi" "Ethernet" "USB 10/100/1000 LAN"; do
        networksetup -setwebproxystate "$svc" off 2>/dev/null
        networksetup -setsecurewebproxystate "$svc" off 2>/dev/null
    done
else
    echo -e "${YELLOW}Not: Sistem proxy'sini kapatmak için sudo ile çalıştırın:${NC}"
    echo "  sudo $0"
    echo ""
    echo "Veya elle kapatın:"
    echo "  Sistem Tercihleri → Ağ → Proxy → HTTP/HTTPS proxy'yi kapatın"
fi

echo -e "${GREEN}ForMacDPI durduruldu.${NC}"
