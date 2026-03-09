# ForMacDPI

<p align="center">
  <strong>macOS için DPI (Deep Packet Inspection) Bypass Aracı</strong><br>
  <em>Windows'taki GoodbyeDPI'ın macOS'a uyarlanmış hali</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.6.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/platform-macOS%2010.15+-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen" alt="Dependencies">
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License">
</p>

---

## Ne Yapar?

İnternet servis sağlayıcılarının (ISP) kullandığı **DPI (Derin Paket İnceleme)** sistemlerini atlatarak engellenen sitelere erişim sağlar. VPN kullanmadan, hız kaybı olmadan çalışır.

**Türkiye'de Discord, X (Twitter), Pastebin, Imgur vb. engellenen sitelere erişim sağlar.**

> ⚠️ Bu araç yalnızca eğitim ve araştırma amaçlıdır. Kullanım sorumluluğu kullanıcıya aittir.

## Özellikler

- 🚀 **Sıfır bağımlılık** — Sadece Python standart kütüphanesi
- 🔒 **VPN değil** — Trafiğinizi şifrelemez veya yönlendirmez, sadece paketleri parçalar
- ⚡ **Hız kaybı yok** — Akıllı mod: sadece engelli sitelere bypass uygulanır
- 🌐 **DNS-over-HTTPS** — DNS engelini de atlatır (Cloudflare + Google)
- 🍎 **macOS native** — `TCP_NOPUSH` ile kesin TCP segment ayrımı
- 🔧 **Otomatik proxy** — Sistem proxy ayarlarını otomatik yapar ve geri alır
- 🧪 **Otomatik test** — Başlangıçta Discord'a bağlantı testi yapar

## Nasıl Çalışır?

DPI sistemleri, ağ trafiğindeki paketleri analiz ederek belirli sitelere erişimi engeller. ForMacDPI, bu paketleri **parçalayarak** veya **bozarak** DPI'ın siteyi tanımasını engeller. Sunucu tarafında ise parçalar birleştirilerek orijinal istek elde edilir — bağlantı %100 sağlıklı çalışır.

```
┌─────────┐         ┌─────┐         ┌──────────┐
│ Tarayıcı │ ──────▶ │ DPI │ ──────▶ │  Sunucu  │
└─────────┘         └─────┘         └──────────┘

  Normal:     [discord.com]  →  DPI "discord.com" görür  →  ❌ ENGELLENDİ

  ForMacDPI:  [disc] + [OOB] + [ord.com]  →  DPI anlam veremez  →  ✅ GEÇTİ
              Sunucu OOB'yi çıkarır → "discord.com" = temiz bağlantı
```

## Teknikler

| Teknik | Açıklama |
|--------|----------|
| **TCP OOB Desync** | TCP Urgent (Out-of-Band) data ile DPI'ın stream parse'ını bozar. 3 mod: `classic`, `prefix`, `mid` |
| **Multi-Record TLS Split** | ClientHello'yu N adet geçerli TLS record'a böler — DPI reassembly yapamaz |
| **TCP_NOPUSH Segment Split** | macOS'a özgü TCP_NOPUSH flag'i ile paketlerin kesin ayrı gitmesini sağlar |
| **TCP Segmentation** | SNI sınırında TCP segmentlerine böler (GoodbyeDPI tekniği) |
| **HTTP Host Fragmentation** | HTTP Host başlığını parçalara ayırır |
| **Host Case Mixing** | `example.com` → `eXaMpLe.CoM` (DPI eşleşme bozar) |
| **Fake Packet (TTL trick)** | Düşük TTL'li sahte paket gönderir — DPI görür ama sunucuya ulaşmaz |
| **DNS-over-HTTPS** | Cloudflare (1.1.1.1) ve Google (8.8.8.8) üzerinden şifreli DNS çözümleme |

## Kurulum

### Gereksinimler

- **macOS 10.15+** (Catalina ve üzeri)
- **Python 3.8+**
- Ek paket kurulumu **gerekmez**

### Adımlar

```bash
# 1. Repoyu klonla
git clone https://github.com/KULLANICI_ADI/formacdpi.git
cd formacdpi

# 2. Python kontrolü (macOS'ta genellikle yüklü gelir)
python3 --version

# Yoksa kur:
brew install python3
# veya
xcode-select --install

# 3. Çalıştırma izni ver
chmod +x start.sh stop.sh
```

## Kullanım

### Hızlı Başlatma (Önerilen)

```bash
# 🇹🇷 Türkiye için en iyi mod — OOB Prefix (ÖNERİLEN)
sudo python3 formacdpi.py -8 -v

# veya shell script ile (varsayılan: -6 Türkiye modu)
sudo ./start.sh
```

> `sudo` sistem proxy ayarlarını otomatik yapmak için gereklidir. `--no-auto-proxy` ile sudo'suz da çalışabilir.

### Stratejiler

| Flag | Strateji | Açıklama |
|------|----------|----------|
| `-1` | Temel SNI Parçalama | Varsayılan, basit TCP segmentation |
| `-2` | SNI + Host Karışık Harf | Host case mixing ekler |
| `-3` | SNI Çoklu Parçalama | 3 segment'e böler |
| `-4` | SNI + Sahte Paket | TTL trick ile fake packet |
| `-5` | Tam Agresif | Tüm teknikler birlikte |
| `-6` | 🇹🇷 Türkiye v1 | Klasik OOB Desync |
| `-7` | 🇹🇷 Türkiye v1 Alt | OOB + Record Split |
| `-8` | 🇹🇷 **Türkiye v2 (ÖNERİLEN)** | OOB Prefix — en etkili |
| `-9` | 🇹🇷 Türkiye v3 | OOB SNI Ortası + Multi-Record |

```bash
# Önerilen (Türkiye)
sudo python3 formacdpi.py -8 -v

# Çalışmazsa alternatifler deneyin:
sudo python3 formacdpi.py -9 -v    # OOB SNI ortası
sudo python3 formacdpi.py -6 -v    # Klasik OOB
sudo python3 formacdpi.py -5 -v    # Agresif mod
```

### Gelişmiş Seçenekler

```bash
# Farklı port
sudo python3 formacdpi.py -8 --port 9090

# Detaylı log
sudo python3 formacdpi.py -8 -v

# Debug modu (çok detaylı)
sudo python3 formacdpi.py -8 --debug

# Otomatik proxy ayarlamadan çalıştır (elle yapılandır)
python3 formacdpi.py -8 --no-auto-proxy

# Tüm trafiğe bypass uygula (varsayılan: sadece engelli siteler)
sudo python3 formacdpi.py -8 --all-traffic

# Güvenli DNS'i kapat
sudo python3 formacdpi.py -8 --no-dns

# Özel fragment boyutu ve gecikme
sudo python3 formacdpi.py -8 --fragment-size 3 --fragment-delay 0.15

# OOB'yi manuel aktif et (herhangi bir strateji için)
sudo python3 formacdpi.py -5 --oob

# Başlangıç testini atla
sudo python3 formacdpi.py -8 --no-test
```

### Durdurma

```bash
# Ctrl+C ile durdur (proxy ayarları otomatik geri yüklenir)

# veya ayrı terminalde:
sudo ./stop.sh
```

### Sudo'suz Kullanım

```bash
# Proxy elle ayarlanır, sudo gerekmez
python3 formacdpi.py -8 --no-auto-proxy

# Sonra tarayıcıda veya sistem ayarlarında proxy olarak ayarlayın:
# HTTP Proxy:  127.0.0.1:8880
# HTTPS Proxy: 127.0.0.1:8880
```

## Engelli Site Listesi

ForMacDPI varsayılan olarak **akıllı mod** ile çalışır: sadece bilinen engelli sitelere DPI bypass uygulanır, diğer siteler direkt geçer — böylece hız kaybı sıfır olur.

Desteklenen engelli siteler:
- **Discord** — discord.com, discordapp.com, cdn, gateway vb.
- **X / Twitter** — x.com, twitter.com, twimg.com, t.co
- **Diğer** — Pastebin, Imgur, Archive.org, SoundCloud, Medium

> Tüm trafiğe bypass uygulamak için `--all-traffic` flag'ini kullanın.

## OOB Desync Modları (v2.5+)

ForMacDPI'ın en güçlü tekniği **TCP OOB (Out-of-Band) Desync**'tir. 3 farklı mod sunar:

### 🟢 Prefix Modu (`-8`, Önerilen)
```
OOB byte → ClientHello
DPI görür: \x00 + 0x16... → "Bu TLS değil" → atlar
Sunucu:    OOB çıkarır → 0x16... = temiz ClientHello ✅
```

### 🔵 Classic Modu (`-6`)
```
[SNI öncesi] → OOB byte → [SNI + devam]
DPI görür: ...disc\x00ord.com... → SNI eşleşmez
Sunucu:    OOB çıkarır → discord.com = temiz ✅
```

### 🟣 Mid Modu (`-9`)
```
[SNI ortasına kadar] → OOB byte → [SNI devamı]
DPI görür: "disco\x00rd.com" → eşleşme yok
Sunucu:    OOB çıkarır → "discord.com" = temiz ✅
```

## Testler

```bash
# Unit testleri çalıştır
python3 test_formacdpi.py
```

Testler şunları kontrol eder:
- SNI extraction ve offset hesaplama
- HTTP Host parsing ve manipülasyon
- CONNECT / HTTP proxy request parsing
- Host case mixing (`example.com` → `eXaMpLe.CoM`)
- TCP segmentation ve TLS record splitting
- OOB desync veri bütünlüğü
- Fake ClientHello üretimi

## Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| `Permission denied` | `sudo` ile çalıştırın |
| Discord hâlâ açılmıyor | `-9` veya `-6` gibi farklı strateji deneyin |
| Bağlantı yavaş | `--only-blocked` (varsayılan) aktif mi kontrol edin |
| DNS çözümlenemiyor | `--no-dns` ile deneyin, ISP DNS'i çalışıyor olabilir |
| Proxy ayarlanmıyor | `--no-auto-proxy` ile başlatıp tarayıcıda elle ayarlayın |
| Port kullanımda | `--port 9090` gibi farklı port deneyin |
| `python3 bulunamadı` | `brew install python3` veya `xcode-select --install` |

## Mimari

```
formacdpi/
├── formacdpi.py        # Ana uygulama (proxy + DPI bypass motoru)
├── test_formacdpi.py   # Unit testler
├── start.sh            # Hızlı başlatma scripti
├── stop.sh             # Durdurma scripti
└── README.md
```

### Bileşenler

| Bileşen | Açıklama |
|---------|----------|
| **SecureDNS** | DoH (DNS-over-HTTPS) + UDP DNS + sistem DNS fallback zinciri |
| **DPIBypass** | Tüm bypass tekniklerini barındıran motor (OOB, TLS split, TCP segment vb.) |
| **ProxyServer** | asyncio tabanlı HTTP/HTTPS proxy sunucusu |
| **MacOSProxy** | macOS sistem proxy ayarlarını otomatik yöneten sınıf |

## Teknik Detaylar

- Python `asyncio` ile asenkron çalışır — yüzlerce eşzamanlı bağlantıyı destekler
- macOS `TCP_NOPUSH` flag'i ile kernel seviyesinde TCP segment ayrımı sağlar
- `TCP_NODELAY` (Nagle off) + `TCP_NOPUSH` (cork/uncork) kombinasyonu kullanır
- DNS cache (1 saat TTL) ile gereksiz DNS sorgusu yapmaz
- 256KB buffer ile minimum syscall overhead
- Graceful shutdown: `SIGINT`/`SIGTERM` ile temiz kapanış ve proxy geri alma
- **Platform**: macOS 10.15+ (Catalina, Big Sur, Monterey, Ventura, Sonoma, Sequoia)

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik ekle'`)
4. Branch'inizi push edin (`git push origin feature/yeni-ozellik`)
5. Pull Request açın

## Teşekkürler

- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) — Windows DPI bypass (ilham kaynağı)
- [byedpi](https://github.com/hufrea/byedpi) — OOB Desync tekniği
- [zapret](https://github.com/bol-van/zapret) — DPI bypass araştırmaları

## Lisans

MIT License — Detaylar için [LICENSE](LICENSE) dosyasına bakın.
