# ForMacDPI v2.0

macOS için DPI (Deep Packet Inspection) bypass aracı. Windows'taki ForMacDPI'nin macOS uyarlaması.

## Ne Yapar?

İnternet servis sağlayıcılarının (ISP) kullandığı DPI (Derin Paket İnceleme) sistemlerini atlatarak, engellenen sitelere erişim sağlar. **Türkiye'de Discord, Twitter vb. engellenen sitelere erişim sağlar.**

## v2.0 Yenilikler

| Yenilik | Açıklama |
|---------|----------|
| **🔥 TLS Record Splitting** | ClientHello'yu iki ayrı TLS record'a böler — DPI birden fazla record'u birleştirmeyi bilmez |
| **⚡ Raw Socket Send** | `socket.sendall()` ile TCP segment'lerin GERÇEKTEN ayrı gitmesini sağlar |
| **🌐 Güvenli DNS** | 8.8.8.8 / 1.1.1.1 üzerinden DNS çözümler — DNS engelini de atlatır |
| **🇹🇷 Türkiye Modu (-6)** | Türkiye DPI'ı için optimize edilmiş preset |

## Teknikler

| Teknik | Açıklama |
|--------|----------|
| **TLS Record Splitting** | ClientHello'yu SNI sınırında 2 geçerli TLS record'a böler |
| **TCP Segmentation** | Her record'u ayrı TCP segment olarak gönderir |
| **SNI Fragmentation** | SNI hostname'in ilk byte'ından böler (DPI hostname göremez) |
| **HTTP Host Fragmentation** | HTTP isteklerindeki Host başlığını parçalar |
| **Host Case Mixing** | `example.com` → `eXaMpLe.CoM` |
| **Fake Packet (TTL trick)** | Düşük TTL'li sahte paket — DPI görür ama sunucuya ulaşmaz |
| **Secure DNS** | 8.8.8.8/1.1.1.1 üzerinden DNS çözümleme |

## Kurulum

Gereksinimler:
- macOS 10.15+ (Catalina ve üzeri)
- Python 3.8+

```bash
# Python 3 kontrolü
python3 --version

# Yoksa kur
brew install python3
# veya
xcode-select --install
```

Ek paket kurulumu **gerekmez** — sadece Python standart kütüphanesi kullanılır.

## Kullanım

### Hızlı Başlatma (Türkiye)

```bash
cd formacdpi

# 🇹🇷 Türkiye modu — Discord, Twitter vb. için önerilen
sudo python3 formacdpi.py -6 -v

# veya shell script ile
sudo ./start.sh
```

### Stratejiler

```bash
sudo python3 formacdpi.py -1    # Temel SNI parçalama (varsayılan)
sudo python3 formacdpi.py -2    # SNI + Host karışık harf
sudo python3 formacdpi.py -3    # SNI çoklu parçalama (3 segment)
sudo python3 formacdpi.py -4    # SNI + sahte paket (TTL trick)
sudo python3 formacdpi.py -5    # Tam agresif (tüm teknikler)
sudo python3 formacdpi.py -6    # 🇹🇷 Türkiye modu (önerilen)
```

### Gelişmiş Seçenekler

```bash
# Farklı port
sudo python3 formacdpi.py --port 9090

# Detaylı log
sudo python3 formacdpi.py -v

# Debug modu
sudo python3 formacdpi.py --debug

# Otomatik proxy ayarlamadan çalıştır (elle yapılandır)
python3 formacdpi.py --no-auto-proxy --port 8880

# Özel fragment boyutu
sudo python3 formacdpi.py -5 --fragment-size 3

# Sahte paket TTL değeri
sudo python3 formacdpi.py -4 --fake-ttl 5

# Güvenli DNS'i kapat (kendi DNS'ini kullan)
sudo python3 formacdpi.py -6 --no-dns

# TLS record splitting kapat
sudo python3 formacdpi.py --no-record-split

# Fragment gecikme ayarla
sudo python3 formacdpi.py --fragment-delay 0.15
```

### Durdurma

```bash
# Ctrl+C ile durdur (proxy ayarları otomatik geri yüklenir)

# veya ayrı terminalde
sudo ./stop.sh
```

### Sudo'suz Kullanım

```bash
# Proxy elle ayarlanır, sudo gerekmez
python3 formacdpi.py --no-auto-proxy --port 8880

# Sonra tarayıcıda proxy ayarı:
# HTTP Proxy:  127.0.0.1:8880
# HTTPS Proxy: 127.0.0.1:8880
```

## Nasıl Çalışır?

```
┌─────────┐     ┌──────────────────┐     ┌──────────┐     ┌────────┐
│ Tarayıcı │ ──→ │ ForMacDPI   │ ──→ │   ISP    │ ──→ │ Sunucu │
│          │     │ (proxy)          │     │  (DPI)   │     │        │
│          │     │                  │     │          │     │        │
│ GET ...  │     │ 1. Paketi al     │     │ SNI'ı    │     │ Normal │
│ Host: x  │     │ 2. SNI/Host bul  │     │ göremez  │     │ yanıt  │
│          │     │ 3. Parçala       │     │ → Geçir! │     │        │
│          │     │ 4. Ayrı TCP'ler  │     │          │     │        │
│          │     │    olarak gönder │     │          │     │        │
└─────────┘     └──────────────────┘     └──────────┘     └────────┘
```

### TLS Record Splitting (v2 Ana Teknik)

```
Normal TLS ClientHello (tek record):
  [TLS Record: len=200][ClientHello...SNI:discord.com...] → DPI "discord.com" görür → ENGEL!

ForMacDPI v2 (iki record):
  Record 1: [TLS Record: len=56][ClientHello...SNI alanına kadar] → SNI yok!
  Record 2: [TLS Record: len=144][discord.com + geri kalan]       → DPI burayı ayrıştıramaz
  → Sunucu iki record'u birleştirir → Normal çalışır!
  → DPI tek record'da SNI arar, bulamaz → Geçir!
```

## Sorun Giderme

### "Permission denied" hatası
```bash
sudo python3 formacdpi.py
```

### Site hala açılmıyor
1. Türkiye modu deneyin: `-6`
2. Verbose açın sorunları görün: `-6 -v`
3. Tüm teknikleri deneyin: `-5`
4. Gecikmeyi artırın: `--fragment-delay 0.2`

### Proxy ayarı geri yüklenmiyor
```bash
sudo ./stop.sh
# veya elle:
# Sistem Tercihleri → Ağ → Gelişmiş → Proxy → HTTP/HTTPS proxy kapatın
```

### DNS bazlı engelleme
v2.0 güvenli DNS'i otomatik olarak kullanır (8.8.8.8/1.1.1.1).
Ek bir DNS ayarı yapmanıza gerek yoktur.

Kapatmak isterseniz: `--no-dns`

## Teknik Detaylar

- **Dil**: Python 3.8+ (sadece standart kütüphane)
- **Mimari**: asyncio tabanlı HTTP CONNECT proxy
- **TLS Bypass**: Record splitting (tek record → 2 record) + TCP segmentation
- **Fragment Gönderim**: Raw `socket.sendall()` + `TCP_NODELAY` + configurable delay
- **DNS**: UDP query to 8.8.8.8/1.1.1.1 (DNS poisoning bypass)
- **Platform**: macOS 10.15+ (Catalina, Big Sur, Monterey, Ventura, Sonoma, Sequoia)
- **Bağımlılık**: Yok (pure Python)

## Lisans

MIT — Kişisel kullanım için serbesttir.
