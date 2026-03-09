#!/usr/bin/env python3
"""
ForMacDPI v2.5.0 — macOS DPI (Deep Packet Inspection) Bypass Tool

Windows'taki ForMacDPI'nin macOS'a uyarlanmış hali.
HTTP proxy olarak çalışır, TLS/HTTP trafiğini parçalayarak DPI'ı atlatır.

v2.5 Yenilikler:
  - OOB Prefix modu: OOB byte'ı ClientHello'dan ÖNCE gönderir.
    DPI: \x00 + 0x16... görür → geçerli TLS değil → atlar!
    Sunucu: OOB çıkarır → 0x16... = temiz ClientHello.
  - OOB SNI Ortası modu: OOB byte'ı SNI hostname'in ORTASINA koyar.
    DPI: "disco\x00rd.com" → eşleşme YOK.
    Sunucu: OOB çıkarır → "discord.com" = temiz.
  - 3 farklı OOB modu: classic (v2.4), prefix (v2.5), mid (v2.5)
  - Daha kısa gecikme süresi: 5-10ms (DPI reassembly'yi atlatır)
  - Tüm v2.4 teknikleri: OOB Desync, Multi-Record TLS Split, TCP_NOPUSH, DoH.

Teknikler:
  1. TCP OOB Desync — 3 mod: classic/prefix/mid
  2. Multi-Record TLS Split (ClientHello'yu N adet geçerli TLS record'a böl)
  3. TCP_NOPUSH Segment Separation (macOS'ta kesin ayrı TCP paket)
  4. TCP Segmentation (SNI sınırında böl)
  5. HTTP Host header fragmentation
  6. Host header case mixing (eXaMpLe.CoM)
  7. DNS-over-HTTPS (1.1.1.1/8.8.8.8 DoH + UDP fallback)

Kullanım:
  sudo python3 formacdpi.py -8                   # Türkiye v2 — OOB Prefix (ÖNERİLEN)
  sudo python3 formacdpi.py -9                   # Türkiye v3 — OOB SNI Ortası
  sudo python3 formacdpi.py -6                   # Türkiye v1 — klasik OOB
  sudo python3 formacdpi.py -5                   # Agresif mod
  sudo python3 formacdpi.py --port 8881          # Farklı port
  sudo python3 formacdpi.py --no-auto-proxy      # Proxy'yi elle ayarla
  sudo python3 formacdpi.py --no-dns             # Güvenli DNS'i kapat

Gereksinimler: Python 3.8+, macOS 10.15+
"""

import asyncio
import socket
import struct
import argparse
import subprocess
import signal
import sys
import os
import logging
import time
import re
import random
import json
import ssl
from typing import Optional, Tuple, List

# ═══════════════════════════════════════════════════════════════
# Sabitler
# ═══════════════════════════════════════════════════════════════

VERSION = "2.6.0"
DEFAULT_PORT = 8880
BUFFER_SIZE = 262144  # 256KB — büyük buffer = daha az syscall = daha hızlı
CONNECT_TIMEOUT = 10
RELAY_TIMEOUT = 300
DRAIN_THRESHOLD = 524288  # 512KB — drain sadece buffer bu kadar dolunca yapılır

# Engelli site listesi — sadece bunlara DPI bypass uygulanır (--only-blocked)
# Diğer tüm siteler direkt geçer → hız düşüşü SIFIR
BLOCKED_DOMAINS = [
    # Discord
    'discord.com',
    'discord.gg',
    'discordapp.com',
    'discord.media',
    'discordcdn.com',
    'gateway.discord.gg',
    'cdn.discordapp.com',
    'media.discordapp.net',
    'images-ext-1.discordapp.net',
    'images-ext-2.discordapp.net',
    # Diğer sık engellenen siteler (Türkiye)
    'x.com',
    'twitter.com',
    'twimg.com',
    't.co',
    'pastebin.com',
    'imgur.com',
    'i.imgur.com',
    'archive.org',
    'web.archive.org',
    'soundcloud.com',
    'medium.com',
]

# ═══════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='\033[90m%(asctime)s\033[0m %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('formacdpi')


# ═══════════════════════════════════════════════════════════════
# Güvenli DNS Çözümleyici (DNS engelini atlatır)
# ═══════════════════════════════════════════════════════════════

class SecureDNS:
    """DNS sorgularını DoH (DNS-over-HTTPS) ve UDP üzerinden yapar.
    Türkiye gibi DNS engeli olan ülkelerde hem DNS poisoning'i
    hem de UDP DNS engelini atlatır.

    Sıralama: DoH (HTTPS) → UDP DNS → Sistem DNS
    """

    DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
    DOH_SERVERS = [
        ('1.1.1.1', 'cloudflare-dns.com', '/dns-query'),
        ('8.8.8.8', 'dns.google', '/resolve'),
    ]
    _cache: dict = {}

    @classmethod
    async def resolve(cls, hostname: str) -> Optional[str]:
        """Hostname'i IP adresine çözümle."""
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass

        if hostname in cls._cache:
            ip, ts = cls._cache[hostname]
            if time.time() - ts < 3600:  # 1 saat cache — DNS'e gereksiz gitmez
                return ip

        # 1. DNS-over-HTTPS (en güvenli — HTTPS engeli yok)
        try:
            ip = await cls._doh_resolve(hostname)
            if ip:
                cls._cache[hostname] = (ip, time.time())
                log.debug(f"  DNS (DoH): {hostname} → {ip}")
                return ip
        except Exception:
            pass

        # 2. UDP DNS (hızlı ama engellenebilir)
        for server in cls.DNS_SERVERS:
            try:
                ip = await cls._query_dns(hostname, server)
                if ip:
                    cls._cache[hostname] = (ip, time.time())
                    log.debug(f"  DNS (UDP): {hostname} → {ip} (via {server})")
                    return ip
            except Exception as e:
                log.debug(f"  DNS UDP hatası ({server}): {e}")
                continue

        # 3. Sistem DNS (son çare — poisoning riski var)
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None, socket.AF_INET)
            if result:
                ip = result[0][4][0]
                cls._cache[hostname] = (ip, time.time())
                log.debug(f"  DNS (sistem): {hostname} → {ip}")
                return ip
        except Exception:
            pass

        return None

    @classmethod
    async def _doh_resolve(cls, hostname: str) -> Optional[str]:
        """DNS-over-HTTPS ile çözümle. UDP engeli olan yerlerde çalışır."""
        for server_ip, server_host, path in cls.DOH_SERVERS:
            try:
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        server_ip, 443, ssl=ctx,
                        server_hostname=server_host
                    ),
                    timeout=5
                )

                req = (
                    f"GET {path}?name={hostname}&type=A HTTP/1.1\r\n"
                    f"Host: {server_host}\r\n"
                    f"Accept: application/dns-json\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()

                writer.write(req)
                await writer.drain()

                response = b""
                try:
                    while len(response) < 8192:
                        chunk = await asyncio.wait_for(
                            reader.read(4096), timeout=5
                        )
                        if not chunk:
                            break
                        response += chunk
                except (asyncio.TimeoutError, ConnectionError):
                    pass

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

                # HTTP response body'yi ayrıştır
                if b'\r\n\r\n' not in response:
                    continue

                headers_part, body = response.split(b'\r\n\r\n', 1)

                # Chunked transfer encoding desteği
                if b'chunked' in headers_part.lower():
                    decoded = b''
                    remaining = body
                    while remaining:
                        nl = remaining.find(b'\r\n')
                        if nl == -1:
                            break
                        try:
                            size = int(remaining[:nl], 16)
                        except ValueError:
                            break
                        if size == 0:
                            break
                        decoded += remaining[nl+2:nl+2+size]
                        remaining = remaining[nl+2+size+2:]
                    body = decoded

                data = json.loads(body)
                for answer in data.get('Answer', []):
                    if answer.get('type') == 1:  # A record
                        ip = answer.get('data')
                        if ip:
                            return ip

            except Exception as e:
                log.debug(f"  DoH hatası ({server_ip}): {e}")
                continue

        return None

    @classmethod
    async def _query_dns(cls, hostname: str, server: str,
                         timeout: float = 3.0) -> Optional[str]:
        """UDP DNS sorgusu gönder ve yanıtı ayrıştır."""
        txn_id = random.randint(0, 65535)

        header = struct.pack('!HHHHHH', txn_id, 0x0100, 1, 0, 0, 0)

        question = b''
        for label in hostname.split('.'):
            question += bytes([len(label)]) + label.encode('ascii')
        question += b'\x00'
        question += struct.pack('!HH', 1, 1)

        query = header + question

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            await loop.sock_sendto(sock, query, (server, 53))
            response = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=timeout
            )
            return cls._parse_dns_response(response, txn_id)
        finally:
            sock.close()

    @classmethod
    def _parse_dns_response(cls, response: bytes,
                            expected_txn: int) -> Optional[str]:
        """DNS yanıtını ayrıştır, ilk A kaydını döndür."""
        if len(response) < 12:
            return None

        txn_id = struct.unpack('!H', response[0:2])[0]
        if txn_id != expected_txn:
            return None

        flags = struct.unpack('!H', response[2:4])[0]
        if flags & 0x000F != 0:
            return None

        qdcount = struct.unpack('!H', response[4:6])[0]
        ancount = struct.unpack('!H', response[6:8])[0]

        pos = 12
        for _ in range(qdcount):
            while pos < len(response) and response[pos] != 0:
                if response[pos] & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += response[pos] + 1
            else:
                pos += 1
            pos += 4

        for _ in range(ancount):
            if pos >= len(response):
                break

            if pos < len(response) and response[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(response) and response[pos] != 0:
                    pos += response[pos] + 1
                pos += 1

            if pos + 10 > len(response):
                break

            rtype = struct.unpack('!H', response[pos:pos + 2])[0]
            pos += 2 + 2 + 4
            rdlength = struct.unpack('!H', response[pos:pos + 2])[0]
            pos += 2

            if rtype == 1 and rdlength == 4 and pos + 4 <= len(response):
                ip = '.'.join(str(b) for b in response[pos:pos + 4])
                return ip

            pos += rdlength

        return None


# ═══════════════════════════════════════════════════════════════
# TLS Protokol Ayrıştırıcı
# ═══════════════════════════════════════════════════════════════

def parse_tls_client_hello(data: bytes) -> Optional[dict]:
    """TLS ClientHello paketini ayrıştır. SNI ve offset bilgisi döndür."""
    try:
        if len(data) < 5 or data[0] != 0x16:  # Handshake
            return None

        record_len = struct.unpack('!H', data[3:5])[0]

        pos = 5
        if pos >= len(data) or data[pos] != 0x01:  # ClientHello
            return None

        pos += 1
        hs_len = struct.unpack('!I', b'\x00' + data[pos:pos+3])[0]
        pos += 3

        # Client version (2) + random (32)
        pos += 34

        # Session ID
        if pos >= len(data):
            return None
        sid_len = data[pos]
        pos += 1 + sid_len

        # Cipher suites
        if pos + 2 > len(data):
            return None
        cs_len = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 2 + cs_len

        # Compression methods
        if pos >= len(data):
            return None
        comp_len = data[pos]
        pos += 1 + comp_len

        # Extensions
        if pos + 2 > len(data):
            return None
        ext_total = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack('!H', data[pos:pos+2])[0]
            ext_len = struct.unpack('!H', data[pos+2:pos+4])[0]
            pos += 4

            if ext_type == 0x0000:  # SNI
                if pos + 5 > len(data):
                    return None
                # sni_list_len(2) + sni_type(1) + sni_len(2)
                sni_type = data[pos + 2]
                sni_len = struct.unpack('!H', data[pos+3:pos+5])[0]
                sni_offset = pos + 5

                if sni_type == 0x00 and sni_offset + sni_len <= len(data):
                    sni = data[sni_offset:sni_offset+sni_len].decode('ascii', errors='ignore')
                    return {
                        'sni': sni,
                        'sni_offset': sni_offset,
                        'sni_length': sni_len
                    }
                return None

            pos += ext_len

        return None
    except (IndexError, struct.error):
        return None


def extract_sni(data: bytes) -> Optional[str]:
    """TLS ClientHello'dan SNI hostname çıkar."""
    info = parse_tls_client_hello(data)
    return info['sni'] if info else None


# ═══════════════════════════════════════════════════════════════
# HTTP Protokol Ayrıştırıcı
# ═══════════════════════════════════════════════════════════════

def extract_http_host(data: bytes) -> Optional[str]:
    """HTTP isteğinden Host başlığını çıkar."""
    try:
        text = data.decode('latin-1')
        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
                # Port varsa ayır
                if ':' in host and not host.startswith('['):
                    return host.split(':')[0]
                return host
        return None
    except:
        return None


def find_host_header_position(data: bytes) -> Optional[Tuple[int, int]]:
    """HTTP isteğinde Host başlığı değerinin byte offset ve uzunluğunu bul.
    Returns: (offset, length) veya None
    """
    try:
        text = data.decode('latin-1')
        lower = text.lower()

        # "\r\nHost:" veya "Host:" (ilk satır olabilir) ara
        idx = lower.find('\r\nhost:')
        if idx == -1:
            if lower.startswith('host:'):
                idx = 0
            else:
                return None
        else:
            idx += 2  # \r\n atla

        # "Host:" sonrası boşlukları atla
        colon_pos = text.index(':', idx) + 1
        while colon_pos < len(text) and text[colon_pos] == ' ':
            colon_pos += 1

        # Satır sonunu bul
        end_pos = text.index('\r\n', colon_pos)

        return (colon_pos, end_pos - colon_pos)
    except (ValueError, IndexError):
        return None


def parse_connect_request(data: bytes) -> Optional[Tuple[str, int]]:
    """HTTP CONNECT isteğini ayrıştır. (host, port) döndür."""
    try:
        first_line = data.split(b'\r\n')[0].decode('latin-1')
        match = re.match(r'CONNECT\s+(.+):(\d+)\s+HTTP/', first_line)
        if match:
            return (match.group(1), int(match.group(2)))
        return None
    except:
        return None


def parse_http_request(data: bytes) -> Optional[Tuple[str, int, bytes]]:
    """HTTP isteğini ayrıştır. (host, port, modified_request) döndür.
    Proxy formatındaki URL'yi relative URL'ye dönüştürür.
    """
    try:
        text = data.decode('latin-1')
        lines = text.split('\r\n')
        first_line = lines[0]

        # "GET http://example.com/path HTTP/1.1" formatı
        match = re.match(r'(\w+)\s+http://([^/\s]+)(/\S*)?\s+(HTTP/\S+)', first_line)
        if match:
            method = match.group(1)
            host_port = match.group(2)
            path = match.group(3) or '/'
            version = match.group(4)

            host = host_port.split(':')[0]
            port = int(host_port.split(':')[1]) if ':' in host_port else 80

            # URL'yi relative yap
            lines[0] = f'{method} {path} {version}'
            modified = '\r\n'.join(lines).encode('latin-1')

            return (host, port, modified)

        # Normal format — Host başlığından çek
        host = extract_http_host(data)
        if host:
            return (host, 80, data)

        return None
    except:
        return None


# ═══════════════════════════════════════════════════════════════
# DPI Bypass Motoru
# ═══════════════════════════════════════════════════════════════

class DPIBypass:
    """DPI atlatma teknikleri uygular.

    v2.5: OOB desync (3 mod: classic/prefix/mid), TLS record splitting,
    raw socket send, SNI sınır bölme.
    """

    def __init__(self, strategy: dict):
        self.fragment_size = strategy.get('fragment_size', 2)
        self.split_at_sni = strategy.get('split_at_sni', True)
        self.split_http = strategy.get('split_http', True)
        self.mix_host_case = strategy.get('mix_host_case', False)
        self.remove_host_space = strategy.get('remove_host_space', False)
        self.extra_split = strategy.get('extra_split', False)
        self.fake_packet = strategy.get('fake_packet', False)
        self.fake_ttl = strategy.get('fake_ttl', 3)
        self.fragment_delay = strategy.get('fragment_delay', 0.002)
        self.tls_record_split = strategy.get('tls_record_split', True)
        self.num_tls_records = strategy.get('num_tls_records', 2)
        self.use_oob = strategy.get('use_oob', False)
        # v2.5: OOB modu — 'classic' (SNI başı), 'prefix' (veri öncesi), 'mid' (SNI ortası)
        self.oob_mode = strategy.get('oob_mode', None)
        if self.use_oob and not self.oob_mode:
            self.oob_mode = 'classic'

    # --- Host Manipülasyonları ---

    @staticmethod
    def mix_case(hostname: str) -> str:
        """Host adını karışık büyük/küçük harf yap: example.com → eXaMpLe.CoM"""
        return ''.join(
            c.upper() if i % 2 == 1 else c.lower()
            for i, c in enumerate(hostname)
        )

    def manipulate_http_request(self, data: bytes) -> bytes:
        """HTTP isteğine DPI atlatma manipülasyonları uygula."""
        try:
            text = data.decode('latin-1')

            if self.mix_host_case:
                # Host değerini karışık harf yap
                def replace_host(m):
                    return m.group(1) + self.mix_case(m.group(2))
                text = re.sub(
                    r'(\r\nHost:\s*)([^\r\n]+)',
                    replace_host,
                    text,
                    count=1,
                    flags=re.IGNORECASE
                )

            if self.remove_host_space:
                # "Host: value" → "Host:value"
                text = re.sub(
                    r'(\r\nHost:)\s+',
                    r'\1',
                    text,
                    count=1,
                    flags=re.IGNORECASE
                )

            return text.encode('latin-1')
        except:
            return data

    # --- Parçalama ---

    def create_fragments(self, data: bytes,
                          split_offsets: Optional[List[int]] = None) -> List[bytes]:
        """Veriyi DPI'ı atlatacak şekilde parçala.

        split_offsets verilmişse: belirtilen noktalarda böl (2-3 büyük parça)
        split_offsets yoksa: fragment_size'a göre genel parçala
        """
        if split_offsets:
            offsets = sorted(set(o for o in split_offsets if 0 < o < len(data)))
            if offsets:
                fragments = []
                prev = 0
                for o in offsets:
                    fragments.append(data[prev:o])
                    prev = o
                fragments.append(data[prev:])
                return [f for f in fragments if f]

        # Genel parçalama (split_offset yoksa)
        frag_size = max(1, self.fragment_size)
        return [data[i:i+frag_size] for i in range(0, len(data), frag_size)]

    # --- TLS Record Splitting (v2 Ana Teknik) ---

    def split_tls_records(self, data: bytes,
                          split_offset: int) -> List[bytes]:
        """Tek TLS record'u iki geçerli TLS record'a böl.

        Çoğu DPI tek record içinde SNI arar. İki ayrı record'u
        birleştirip ayrıştırmayı bilmez.

        data: Orijinal TLS record (5 byte header + payload)
        split_offset: data başlangıcından itibaren bölme noktası
        """
        if len(data) < 6 or data[0] != 0x16:
            return [data]

        record_type = data[0:1]
        record_version = data[1:3]
        payload = data[5:]

        payload_split = split_offset - 5
        if payload_split <= 0 or payload_split >= len(payload):
            return [data]

        part1 = payload[:payload_split]
        part2 = payload[payload_split:]

        record1 = (
            record_type + record_version
            + struct.pack('!H', len(part1))
            + part1
        )
        record2 = (
            record_type + record_version
            + struct.pack('!H', len(part2))
            + part2
        )

        return [record1, record2]

    def split_tls_records_multi(self, data: bytes, sni_offset: int,
                                 sni_length: int,
                                 num_records: int = 6) -> List[bytes]:
        """ClientHello'yu N adet küçük TLS record'a böl.

        DPI tek record'da SNI arar — 2 record'u birleştirmeyi bazen bilir.
        Ama 6-8 record'u birleştirmesi ÇOK ZOR:
          - Buffer overflow: DPI'ın reassembly buffer'ı dolabilir
          - Timeout: Fragment'lar arası gecikme ile DPI buffer timeout olur
          - Complexity: N record birleştirme O(N) memory + CPU

        Sunucu için %100 geçerli TLS: RFC 5246 Section 6.2.1'e göre
        bir handshake mesajı birden fazla record'a yayılabilir.

        SNI hostname MUTLAKA bir record sınırında bölünür →
        hiçbir tek record tam SNI'yı içermez.
        """
        if len(data) < 6 or data[0] != 0x16:
            return [data]

        record_type = data[0:1]     # 0x16 (Handshake)
        record_version = data[1:3]  # 0x03 0x01
        payload = data[5:]

        if len(payload) < num_records * 2:
            return [data]

        # SNI konumu (payload içinde, TLS record header hariç)
        sni_in_payload = sni_offset - 5
        sni_mid = sni_in_payload + sni_length // 2

        # Bölme noktaları oluştur
        step = max(1, len(payload) // num_records)
        points = set()

        # Eşit aralıklı bölme noktaları
        for i in range(1, num_records):
            points.add(i * step)

        # SNI bölme noktaları (EN ÖNEMLİ)
        # SNI hostname'den hemen önce ve ortasında böl
        if 0 < sni_in_payload < len(payload):
            points.add(sni_in_payload)
        if 0 < sni_mid < len(payload):
            points.add(sni_mid)

        points = sorted(p for p in points if 0 < p < len(payload))

        # TLS record'ları oluştur
        records = []
        prev = 0
        for p in points:
            chunk = payload[prev:p]
            if chunk:
                records.append(
                    record_type + record_version
                    + struct.pack('!H', len(chunk))
                    + chunk
                )
            prev = p

        # Son parça
        chunk = payload[prev:]
        if chunk:
            records.append(
                record_type + record_version
                + struct.pack('!H', len(chunk))
                + chunk
            )

        return records if len(records) > 1 else [data]

    # --- Raw Socket Fragment Gönderme (v2.2) ---

    async def send_fragmented(self, writer: asyncio.StreamWriter,
                               fragments: List[bytes]):
        """Parçaları AYRI TCP segment'ler olarak gönder.

        v2.2: TCP_NOPUSH (macOS/BSD cork/uncork) ile KESİN segment ayrımı.

        Teknik:
          1. TCP_NODELAY=1 (Nagle kapat)
          2. TCP_NOPUSH=1 (cork: veriyi tut)
          3. sendall(chunk)
          4. TCP_NOPUSH=0 (uncork: buffer'ı ZORLA flush → ayrı TCP segment)
          5. sleep(delay) — segment'in fiziksel olarak gitmesini bekle

        Bu teknik macOS kernel'ini ZORLAR — TCP_NODELAY toggle yetmezdi.
        """
        if writer.is_closing():
            raise ConnectionError("Writer zaten kapatılmış")

        sock = writer.transport.get_extra_info('socket')

        if sock:
            try:
                # macOS/BSD TCP_NOPUSH değeri (Python'da tanımlı olmayabilir)
                TCP_NOPUSH = getattr(socket, 'TCP_NOPUSH', 4)

                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                for i, chunk in enumerate(fragments):
                    # ═══ CORK: veriyi kernel buffer'da tut ═══
                    try:
                        sock.setsockopt(
                            socket.IPPROTO_TCP, TCP_NOPUSH, 1
                        )
                    except OSError:
                        pass

                    # Veriyi yaz
                    sock.sendall(chunk)

                    # ═══ UNCORK: buffer'ı ZORLA flush → ayrı segment ═══
                    try:
                        sock.setsockopt(
                            socket.IPPROTO_TCP, TCP_NOPUSH, 0
                        )
                    except OSError:
                        pass

                    if i < len(fragments) - 1:
                        # Segment'in NIC'den çıkmasını bekle
                        await asyncio.sleep(self.fragment_delay)

                log.debug(
                    f"  → {len(fragments)} TCP segment gönderildi "
                    f"(NOPUSH): {[len(f) for f in fragments]}"
                )
                return
            except Exception as e:
                log.debug(f"Raw socket send hatası ({e}), asyncio fallback")

        for i, chunk in enumerate(fragments):
            writer.write(chunk)
            await writer.drain()
            if i < len(fragments) - 1:
                await asyncio.sleep(self.fragment_delay)

    # --- TCP OOB Desync (v2.4 Ana Teknik) ---

    async def send_with_oob_desync(self, writer: asyncio.StreamWriter,
                                    data: bytes, split_pos: int) -> bool:
        """TCP OOB (Out-of-Band) Desync ile DPI bypass.

        Teknik (byedpi/zapret'ten esinlenme):
          1. ClientHello'yu split_pos noktasında iki TCP segmentine böl
          2. Segment 1'i gönder (SNI öncesi)
          3. 1 byte TCP Urgent (OOB) data gönder
          4. Segment 2'yi gönder (SNI + devam)

        DPI perspektifi:
          TCP stream'i birleştirince: part1 + \\x00 + part2
          OOB byte SNI alanına eklenir → SNI parse bozulur
          Örn: "discord.com" yerine "\\x00discord.com" görür (eşleşmez!)

        Sunucu perspektifi:
          SO_OOBINLINE varsayılan olarak KAPALI (macOS/Linux/BSD)
          OOB byte inline stream'den ÇIKARILIR
          recv() → part1 + part2 = orijinal ClientHello
          TLS handshake normal tamamlanır (%100 uyumlu)

        Bu teknik Türkiye, Rusya, Çin DPI'larında test edilmiş
        ve başarılı sonuç vermiştir (byedpi projesinde).
        """
        sock = writer.transport.get_extra_info('socket')
        if not sock:
            raise ConnectionError("Socket erişilemedi")

        TCP_NOPUSH = getattr(socket, 'TCP_NOPUSH', 4)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        part1 = data[:split_pos]
        part2 = data[split_pos:]

        # ═══ Segment 1: SNI öncesi ═══
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_NOPUSH, 1)
        except OSError:
            pass
        sock.sendall(part1)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_NOPUSH, 0)
        except OSError:
            pass

        await asyncio.sleep(self.fragment_delay)

        # ═══ OOB byte: DPI'ın stream parse'ını bozar ═══
        # TCP Urgent Data — DPI bunu inline görür, sunucu çıkarır
        sock.send(b'\x00', socket.MSG_OOB)

        await asyncio.sleep(self.fragment_delay)

        # ═══ Segment 2: SNI + geri kalan ═══
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_NOPUSH, 1)
        except OSError:
            pass
        sock.sendall(part2)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_NOPUSH, 0)
        except OSError:
            pass

        log.debug(
            f"  → OOB desync: 2 segment + OOB, "
            f"s1={len(part1)}B oob=1B s2={len(part2)}B"
        )
        return True

    # --- TCP OOB Prefix Desync (v2.5 Yeni Teknik) ---

    async def send_with_oob_prefix(self, writer: asyncio.StreamWriter,
                                    data: bytes) -> bool:
        """TCP OOB byte'ı tüm veriden ÖNCE gönder.

        v2.5 Yeni Teknik — DPI'ın TLS tespitini tamamen bozar:
          1. Önce 1 byte TCP Urgent (OOB) data gönder: \\x00
          2. Sonra tüm ClientHello'yu tek parça gönder

        DPI perspektifi:
          TCP stream reassembly: \\x00 + 0x16 0x03 0x01 ...
          İlk byte 0x00 ≠ 0x16 → "Bu TLS değil" → inspeksiyon ATLANIR!
          DPI SNI aramaz çünkü TLS olarak tanımaz.

        Sunucu perspektifi:
          SO_OOBINLINE=off → OOB byte stream'den çıkarılır
          recv() → 0x16 0x03 0x01 ... = temiz ClientHello
          TLS handshake normal tamamlanır (%100 uyumlu)

        Bu teknik DPI'ın OOB byte'ı inline olarak görmesine dayanır.
        Eğer DPI URG flag'i tanıyıp OOB'yi çıkarırsa işe yaramaz.
        """
        sock = writer.transport.get_extra_info('socket')
        if not sock:
            raise ConnectionError("Socket erişilemedi")

        TCP_NOPUSH = getattr(socket, 'TCP_NOPUSH', 4)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # ═══ OOB BYTE FIRST: DPI sees non-TLS stream ═══
        sock.send(b'\x00', socket.MSG_OOB)

        await asyncio.sleep(self.fragment_delay)

        # ═══ Full ClientHello: server sees clean TLS ═══
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_NOPUSH, 1)
        except OSError:
            pass
        sock.sendall(data)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, TCP_NOPUSH, 0)
        except OSError:
            pass

        log.debug(
            f"  → OOB prefix: oob=1B + data={len(data)}B"
        )
        return True

    async def send_fake_tls(self, writer: asyncio.StreamWriter,
                             real_data: bytes):
        """Sahte TLS ClientHello gönder (DPI'ı yanıltmak için).
        Düşük TTL ile gönderilir — DPI görür ama sunucuya ulaşmaz.
        """
        try:
            sock = writer.transport.get_extra_info('socket')
            if not sock:
                return

            # TCP_NODELAY aç — sahte paket ayrı segment olarak gitmeli
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Orijinal TTL'i kaydet
            original_ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)

            # Sahte ClientHello (www.w3.org SNI'lı)
            fake_sni = b'www.w3.org'
            fake_hello = self._build_fake_client_hello(fake_sni)

            # Düşük TTL ayarla
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.fake_ttl)

            # Sahte paketi gönder (raw socket)
            sock.sendall(fake_hello)
            await asyncio.sleep(0.001)

            # TTL'i geri yükle
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original_ttl)

        except Exception as e:
            log.debug(f"Fake packet gönderimi başarısız: {e}")

    @staticmethod
    def _build_fake_client_hello(sni: bytes) -> bytes:
        """Sahte TLS 1.0 ClientHello paketi oluştur."""
        # Minimal ClientHello
        sni_ext = (
            b'\x00\x00'  # SNI extension type
            + struct.pack('!H', len(sni) + 5)  # extension length
            + struct.pack('!H', len(sni) + 3)  # SNI list length
            + b'\x00'  # host_name type
            + struct.pack('!H', len(sni))  # hostname length
            + sni
        )

        extensions = sni_ext
        extensions_data = struct.pack('!H', len(extensions)) + extensions

        # cipher suites (minimal)
        cipher_suites = b'\x00\x02\x00\xff'  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV

        # compression
        compression = b'\x01\x00'

        client_hello_body = (
            b'\x03\x01'           # TLS 1.0
            + os.urandom(32)      # random
            + b'\x00'             # session id length = 0
            + cipher_suites
            + compression
            + extensions_data
        )

        handshake = (
            b'\x01'  # ClientHello
            + struct.pack('!I', len(client_hello_body))[1:]  # 3-byte length
            + client_hello_body
        )

        record = (
            b'\x16'                                    # Handshake
            + b'\x03\x01'                              # TLS 1.0
            + struct.pack('!H', len(handshake))        # length
            + handshake
        )

        return record

    # --- Yüksek Seviye İşlemler ---

    async def process_tls_data(self, writer: asyncio.StreamWriter,
                                data: bytes) -> bool:
        """TLS ClientHello verisini DPI bypass ile gönder.

        v2.4 Strateji (öncelik sırası):
          1. OOB Desync: TCP Urgent Data ile DPI'ın SNI parse'ını boz
          2. TLS Record Split: ClientHello'yu N adet record'a böl (fallback)
          3. TCP Segmentation: SNI sınırında TCP segment böl (fallback)

        Öncelik: OOB Desync > TLS Record Split > TCP Segmentation
        """
        try:
            # SNI offset bul
            info = parse_tls_client_hello(data)

            if info and self.split_at_sni:
                sni_start = info['sni_offset']

                # ═══ OOB DESYNC (v2.5 — 3 mod) ═══
                if self.use_oob:
                    try:
                        if self.oob_mode == 'prefix':
                            # v2.5: OOB byte ÖNCE → DPI TLS tanıyamaz
                            result = await self.send_with_oob_prefix(
                                writer, data
                            )
                        elif self.oob_mode == 'mid':
                            # v2.5: OOB byte SNI ORTASINDA → "disco\x00rd.com"
                            sni_mid = sni_start + info['sni_length'] // 2
                            result = await self.send_with_oob_desync(
                                writer, data, sni_mid
                            )
                        else:
                            # v2.4 classic: OOB byte SNI BAŞINDA
                            result = await self.send_with_oob_desync(
                                writer, data, sni_start
                            )
                        if result:
                            return True
                    except Exception as e:
                        log.debug(f"OOB desync hatası ({self.oob_mode}): {e}, fallback deneniyor")

                # Sahte paket gönder (OOB kullanılmıyorsa)
                if self.fake_packet:
                    await self.send_fake_tls(writer, data)

                # ═══ TLS RECORD SPLITTING (v2.3 multi-record) ═══
                # ClientHello'yu N adet küçük TLS record'a böler.
                # DPI 2 record'u birleştirebilir ama 6-8 record ÇOK ZOR.
                if self.tls_record_split:
                    if self.num_tls_records > 2:
                        # ═══ MULTI-RECORD (v2.3 agresif) ═══
                        fragments = self.split_tls_records_multi(
                            data, sni_start, info['sni_length'],
                            self.num_tls_records
                        )
                    else:
                        # ═══ 2-RECORD SPLIT ═══
                        records = self.split_tls_records(data, sni_start)
                        if self.extra_split and len(records) >= 2:
                            first_record = records[0]
                            fragments = [
                                first_record[:1],
                                first_record[1:],
                                records[1],
                            ]
                        else:
                            fragments = records
                    fragments = [f for f in fragments if f]
                    if len(fragments) >= 2:
                        log.debug(
                            f"  TLS record split: {len(fragments)} record, "
                            f"SNI='{info['sni']}', boyutlar={[len(f) for f in fragments]}"
                        )
                        await self.send_fragmented(writer, fragments)
                        return True

                # ═══ PURE TCP SEGMENTATION (Varsayılan) ═══
                # Windows GoodbyeDPI ile AYNI teknik.
                # Ham byte'ları SNI sınırında ayrı TCP segment'lere böl.
                # Sunucu TCP reassembly → orijinal ClientHello'yu görür.
                # DPI her segment'e AYRI bakar → SNI hostname bulamaz.
                #
                # Segment yapısı (extra_split aktifken):
                #   [0x16]                     ← DPI TLS tanıyamaz
                #   [header...SNI öncesi]       ← SNI yok
                #   [SNI hostname + geri kalan]  ← bağlam yok, DPI atlar

                if self.extra_split and sni_start > 1:
                    # 3 segment: ilk byte + header + SNI kısmı
                    fragments = [
                        data[:1],           # Sadece 0x16
                        data[1:sni_start],  # TLS header + ext (SNI yok)
                        data[sni_start:],   # SNI hostname + devam
                    ]
                else:
                    # 2 segment: SNI öncesi + SNI ve sonrası
                    fragments = [
                        data[:sni_start],
                        data[sni_start:],
                    ]

                fragments = [f for f in fragments if f]
                log.debug(
                    f"  TCP split: {len(fragments)} segment, "
                    f"SNI='{info['sni']}', boyutlar={[len(f) for f in fragments]}"
                )

                await self.send_fragmented(writer, fragments)
                return True

            # SNI bulunamadı — düz gönder
            writer.write(data)
            await writer.drain()
            return True

        except (ConnectionError, OSError) as e:
            # Bağlantı koptu — fragment'sız düz göndermeyi dene
            log.debug(f"TLS fragment hatası ({e}), düz gönderim deneniyor...")
            try:
                writer.write(data)
                await writer.drain()
                return True
            except Exception:
                log.debug("TLS düz gönderim de başarısız")
                return False
        except Exception as e:
            log.error(f"TLS işleme hatası: {type(e).__name__}: {e}")
            return False

    async def process_http_data(self, writer: asyncio.StreamWriter,
                                 data: bytes) -> bool:
        """HTTP istek verisini DPI bypass ile gönder."""
        try:
            # Host manipülasyonları
            data = self.manipulate_http_request(data)

            # Host offset bul ve parçalama noktalarını belirle
            host_info = find_host_header_position(data)
            split_offsets = []

            if host_info and self.split_http:
                offset, length = host_info
                # Host değerinin BAŞINDAN böl (ortasından değil)
                split_offsets.append(offset)

                if self.extra_split and offset > 0:
                    split_offsets.append(min(4, offset - 1))

                log.debug(f"  HTTP split: {len(split_offsets)+1} parça, offsets={sorted(split_offsets)}")

            fragments = self.create_fragments(
                data, split_offsets if split_offsets else None
            )
            await self.send_fragmented(writer, fragments)
            return True
        except Exception as e:
            log.error(f"HTTP işleme hatası: {e}")
            return False


# ═══════════════════════════════════════════════════════════════
# Stratejiler (DPI bypass preset'leri gibi)
# ═══════════════════════════════════════════════════════════════

STRATEGIES = {
    1: {
        'name': 'Temel SNI Parçalama',
        'fragment_size': 2,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': False,
        'remove_host_space': False,
        'extra_split': False,
        'fake_packet': False,
        'fake_ttl': 3,
        'fragment_delay': 0.1,
        'tls_record_split': False,
    },
    2: {
        'name': 'SNI + Host Karışık Harf',
        'fragment_size': 2,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': True,
        'remove_host_space': False,
        'extra_split': False,
        'fake_packet': False,
        'fake_ttl': 3,
        'fragment_delay': 0.1,
        'tls_record_split': False,
    },
    3: {
        'name': 'SNI Çoklu Parçalama',
        'fragment_size': 2,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': False,
        'remove_host_space': False,
        'extra_split': True,
        'fake_packet': False,
        'fake_ttl': 3,
        'fragment_delay': 0.1,
        'tls_record_split': False,
    },
    4: {
        'name': 'SNI + Sahte Paket',
        'fragment_size': 2,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': False,
        'remove_host_space': False,
        'extra_split': False,
        'fake_packet': True,
        'fake_ttl': 3,
        'fragment_delay': 0.1,
        'tls_record_split': False,
    },
    5: {
        'name': 'Tam Agresif (Tümü)',
        'fragment_size': 1,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': True,
        'remove_host_space': True,
        'extra_split': True,
        'fake_packet': True,
        'fake_ttl': 2,
        'fragment_delay': 0.15,
        'tls_record_split': False,
    },
    6: {
        'name': 'Türkiye Modu (OOB Desync)',
        'fragment_size': 1,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': True,
        'remove_host_space': True,
        'extra_split': True,
        'fake_packet': False,
        'fake_ttl': 1,
        'fragment_delay': 0.05,
        'tls_record_split': False,
        'num_tls_records': 2,
        'use_oob': True,
    },
    7: {
        'name': 'Türkiye Alternatif (OOB + Record Split)',
        'fragment_size': 1,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': True,
        'remove_host_space': True,
        'extra_split': True,
        'fake_packet': False,
        'fake_ttl': 1,
        'fragment_delay': 0.1,
        'tls_record_split': True,
        'num_tls_records': 4,
        'use_oob': True,
    },
    8: {
        'name': 'Türkiye v2 (OOB Prefix — ÖNERİLEN)',
        'fragment_size': 1,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': True,
        'remove_host_space': True,
        'extra_split': True,
        'fake_packet': False,
        'fake_ttl': 1,
        'fragment_delay': 0.01,
        'tls_record_split': False,
        'num_tls_records': 2,
        'use_oob': True,
        'oob_mode': 'prefix',
    },
    9: {
        'name': 'Türkiye v3 (OOB SNI Ortası + Records)',
        'fragment_size': 1,
        'split_at_sni': True,
        'split_http': True,
        'mix_host_case': True,
        'remove_host_space': True,
        'extra_split': True,
        'fake_packet': False,
        'fake_ttl': 1,
        'fragment_delay': 0.005,
        'tls_record_split': True,
        'num_tls_records': 6,
        'use_oob': True,
        'oob_mode': 'mid',
    },
}


# ═══════════════════════════════════════════════════════════════
# HTTP Proxy Sunucusu
# ═══════════════════════════════════════════════════════════════

class ProxyServer:
    """HTTP/HTTPS proxy sunucusu — DPI bypass tekniklerini uygular."""

    def __init__(self, bypass: DPIBypass, bind_addr: str = '127.0.0.1',
                 port: int = DEFAULT_PORT, verbose: bool = False,
                 use_secure_dns: bool = True,
                 only_blocked: bool = False):
        self.bypass = bypass
        self.bind_addr = bind_addr
        self.port = port
        self.verbose = verbose
        self.use_secure_dns = use_secure_dns
        self.only_blocked = only_blocked
        self._running = True
        self._server = None
        self._tasks = set()

        # İstatistikler
        self.stats = {
            'total': 0,
            'https': 0,
            'http': 0,
            'active': 0,
            'errors': 0,
            'dns_bypass': 0,
            'start_time': time.time(),
        }

    async def _resolve_host(self, hostname: str, is_blocked: bool = True) -> str:
        """Hostname'i çözümle.

        v2.6: Engelli siteler → DoH (güvenli), diğerleri → sistem DNS (hızlı)
        """
        if self.use_secure_dns and is_blocked:
            # Sadece engelli siteler için DoH kullan — diğerlerine gereksiz yavaşlık
            ip = await SecureDNS.resolve(hostname)
            if ip and ip != hostname:
                self.stats['dns_bypass'] += 1
                return ip
        elif self.use_secure_dns and not is_blocked:
            # Engelli değilse önce cache kontrol, yoksa sistem DNS (en hızlı)
            if hostname in SecureDNS._cache:
                ip, ts = SecureDNS._cache[hostname]
                if time.time() - ts < 3600:
                    return ip
            # Sistem DNS — DoH overhead'i yok
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.getaddrinfo(hostname, None, socket.AF_INET),
                    timeout=3
                )
                if result:
                    ip = result[0][4][0]
                    SecureDNS._cache[hostname] = (ip, time.time())
                    return ip
            except:
                pass
        return hostname

    async def start(self):
        """Proxy sunucusunu başlat."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_addr,
            self.port,
            reuse_address=True
        )
        log.info(f"\033[92m✓\033[0m Proxy dinleniyor: \033[1m{self.bind_addr}:{self.port}\033[0m")

    async def stop(self):
        """Proxy sunucusunu durdur."""
        self._running = False
        # Aktif bağlantıları iptal et
        for task in list(self._tasks):
            task.cancel()
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=3)
            except asyncio.TimeoutError:
                pass

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
        """Gelen bağlantıyı işle."""
        task = asyncio.current_task()
        self._tasks.add(task)
        client_addr = writer.get_extra_info('peername')
        self.stats['total'] += 1
        self.stats['active'] += 1

        try:
            # İlk veriyi oku
            first_data = await asyncio.wait_for(
                reader.readuntil(b'\r\n\r\n'),
                timeout=CONNECT_TIMEOUT
            )

            # CONNECT mı yoksa düz HTTP mi?
            connect_info = parse_connect_request(first_data)

            if connect_info:
                await self._handle_connect(reader, writer, first_data, connect_info)
            else:
                await self._handle_http(reader, writer, first_data)

        except asyncio.TimeoutError:
            log.debug(f"Zaman aşımı: {client_addr}")
        except asyncio.IncompleteReadError:
            pass
        except asyncio.LimitOverrunError:
            log.debug(f"Çok büyük istek başlıkları: {client_addr}")
        except ConnectionError:
            pass
        except Exception as e:
            self.stats['errors'] += 1
            log.debug(f"Bağlantı hatası ({client_addr}): {e}")
        finally:
            self._tasks.discard(task)
            self.stats['active'] -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _handle_connect(self, client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter,
                               request_data: bytes,
                               connect_info: Tuple[str, int]):
        """HTTPS CONNECT tüneli — TLS ClientHello fragmentation."""
        host, port = connect_info
        self.stats['https'] += 1

        if self.verbose:
            log.info(f"\033[96m🔒 HTTPS\033[0m {host}:{port}")

        server_reader = None
        server_writer = None

        try:
            # Engelli mi kontrol et
            blocked = self._is_blocked(host)

            # Güvenli DNS ile hostname çözümle (engelli → DoH, değilse → sistem DNS)
            resolved_host = await self._resolve_host(host, is_blocked=blocked)

            if self.verbose and resolved_host != host:
                log.info(f"  \033[90mDNS: {host} → {resolved_host}\033[0m")

            # Sunucuya bağlan
            try:
                server_reader, server_writer = await asyncio.wait_for(
                    asyncio.open_connection(resolved_host, port),
                    timeout=CONNECT_TIMEOUT
                )
            except (OSError, asyncio.TimeoutError) as e:
                log.debug(f"Sunucuya bağlanılamadı ({host}:{port}): {e}")
                client_writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await client_writer.drain()
                return

            # İstemciye 200 döndür
            client_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await client_writer.drain()

            # İstemciden TLS ClientHello'yu oku
            client_hello = await asyncio.wait_for(
                self._read_tls_record(client_reader),
                timeout=CONNECT_TIMEOUT
            )

            if not client_hello:
                return

            # SNI bilgisi logla
            sni = extract_sni(client_hello)
            if sni and self.verbose:
                log.info(f"  \033[90mSNI: {sni}\033[0m")

            # Engelli değilse direkt gönder (hız kaybı SIFIR) — v2.6: her zaman aktif
            if self.only_blocked and not blocked:
                server_writer.write(client_hello)
                await server_writer.drain()
                if self.verbose:
                    log.info(f"  \033[90m⏩ Direkt (engelli değil)\033[0m")
            else:
                # DPI bypass ile gönder
                success = await self.bypass.process_tls_data(server_writer, client_hello)
                if not success:
                    return

            # Çift yönlü relay
            await asyncio.gather(
                self._relay(client_reader, server_writer, 'C→S'),
                self._relay(server_reader, client_writer, 'S→C'),
            )

        except Exception as e:
            log.debug(f"CONNECT hata ({host}): {e}")
        finally:
            for w in [server_writer]:
                if w:
                    try:
                        w.close()
                        await w.wait_closed()
                    except:
                        pass

    async def _handle_http(self, client_reader: asyncio.StreamReader,
                            client_writer: asyncio.StreamWriter,
                            request_data: bytes):
        """Düz HTTP proxy — Host header fragmentation."""
        self.stats['http'] += 1

        http_info = parse_http_request(request_data)
        if not http_info:
            # Geçersiz istek
            client_writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await client_writer.drain()
            return

        host, port, modified_request = http_info

        if self.verbose:
            log.info(f"\033[93m🌐 HTTP\033[0m  {host}:{port}")

        server_reader = None
        server_writer = None

        try:
            # Engelli mi kontrol et
            blocked = self._is_blocked(host)

            # Güvenli DNS (engelli → DoH, değilse → sistem DNS)
            resolved_host = await self._resolve_host(host, is_blocked=blocked)

            # Sunucuya bağlan
            server_reader, server_writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_host, port),
                timeout=CONNECT_TIMEOUT
            )

            # Engelli değilse direkt gönder — v2.6: her zaman aktif
            if self.only_blocked and not blocked:
                server_writer.write(modified_request)
                await server_writer.drain()
                if self.verbose:
                    log.info(f"  \033[90m⏩ Direkt (engelli değil)\033[0m")
            else:
                success = await self.bypass.process_http_data(server_writer, modified_request)
                if not success:
                    return

            # Çift yönlü relay
            await asyncio.gather(
                self._relay(client_reader, server_writer, 'C→S'),
                self._relay(server_reader, client_writer, 'S→C'),
            )

        except Exception as e:
            log.debug(f"HTTP hata ({host}): {e}")
        finally:
            for w in [server_writer]:
                if w:
                    try:
                        w.close()
                        await w.wait_closed()
                    except:
                        pass

    def _is_blocked(self, hostname: str) -> bool:
        """Hostname engelli site listesinde mi kontrol et.
        Alt domain'leri de eşleştirir: cdn.discord.com → discord.com ✓
        """
        hostname = hostname.lower().strip('.')
        for domain in BLOCKED_DOMAINS:
            if hostname == domain or hostname.endswith('.' + domain):
                return True
        return False

    async def _read_tls_record(self, reader: asyncio.StreamReader) -> Optional[bytes]:
        """Tam TLS kaydı oku (header + payload)."""
        collected = b''
        try:
            header = await asyncio.wait_for(reader.readexactly(5), timeout=10)
            collected = header
            if header[0] != 0x16:
                # TLS değil — ne gelirse geçir
                rest = await reader.read(BUFFER_SIZE)
                return header + rest

            record_len = struct.unpack('!H', header[3:5])[0]

            if record_len > 16384:  # Makul limit
                rest = await reader.read(BUFFER_SIZE)
                return header + rest

            payload = await asyncio.wait_for(
                reader.readexactly(record_len),
                timeout=10
            )
            return header + payload
        except asyncio.IncompleteReadError as e:
            # readexactly kısmen okumuş — partial veriyi kurtar
            collected += e.partial
            try:
                rest = await reader.read(BUFFER_SIZE)
                if rest:
                    collected += rest
            except:
                pass
            return collected if collected else None
        except asyncio.TimeoutError:
            try:
                rest = await reader.read(BUFFER_SIZE)
                if rest:
                    collected += rest
            except:
                pass
            return collected if collected else None

    async def _relay(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter, label: str = ''):
        """Yüksek hızlı çift yönlü veri aktarımı.

        v2.6 Optimizasyon:
          - drain() her write'da DEĞİL, sadece buffer dolunca yapılır
          - Büyük buffer (256KB) = daha az syscall
          - write_eof sadece destekleniyorsa
        """
        try:
            while self._running:
                data = await asyncio.wait_for(
                    reader.read(BUFFER_SIZE),
                    timeout=RELAY_TIMEOUT
                )
                if not data:
                    break
                writer.write(data)
                # drain() sadece buffer çok doluysa — throughput BÜYÜK fark!
                # Her write'da drain = her pakette TCP flush bekleme = YAVAŞ
                # Threshold drain = kernel TCP buffer'ını verimli kullan = HIZLI
                buf_size = writer.transport.get_write_buffer_size()
                if buf_size > DRAIN_THRESHOLD:
                    await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError,
                asyncio.IncompleteReadError):
            pass
        finally:
            try:
                # Son veriyi flush et
                await writer.drain()
            except:
                pass
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except:
                pass


# ═══════════════════════════════════════════════════════════════
# macOS Sistem Proxy Yönetimi
# ═══════════════════════════════════════════════════════════════

class MacOSProxy:
    """macOS sistem proxy ayarlarını yönetir."""

    def __init__(self, port: int):
        self.port = port
        self._services = []
        self._original_settings = {}

    def get_active_service(self) -> Optional[str]:
        """Aktif ağ servisini tespit et."""
        try:
            # Varsayılan route'u bul
            result = subprocess.run(
                ['route', '-n', 'get', 'default'],
                capture_output=True, text=True, timeout=5
            )
            interface = None
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    interface = line.split(':')[1].strip()
                    break

            if not interface:
                return 'Wi-Fi'

            # Interface → service name eşleme
            result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True, text=True, timeout=5
            )
            current_service = None
            for line in result.stdout.split('\n'):
                if line.startswith('Hardware Port:'):
                    current_service = line.split(':', 1)[1].strip()
                elif line.startswith('Device:'):
                    device = line.split(':', 1)[1].strip()
                    if device == interface:
                        return current_service

            return 'Wi-Fi'
        except:
            return 'Wi-Fi'

    def setup(self) -> bool:
        """Sistem proxy'sini ayarla."""
        if os.geteuid() != 0:
            log.warning("Sistem proxy ayarı için sudo gerekli. --no-auto-proxy ile elle ayarlayabilirsiniz.")
            return False

        service = self.get_active_service()
        if not service:
            log.error("Aktif ağ servisi bulunamadı")
            return False

        self._services = [service]

        try:
            # Mevcut ayarları kaydet
            for svc in self._services:
                self._save_current_settings(svc)

            # HTTP proxy ayarla
            for svc in self._services:
                subprocess.run([
                    'networksetup', '-setwebproxy', svc,
                    '127.0.0.1', str(self.port)
                ], capture_output=True, check=True)

                # HTTPS proxy ayarla
                subprocess.run([
                    'networksetup', '-setsecurewebproxy', svc,
                    '127.0.0.1', str(self.port)
                ], capture_output=True, check=True)

                log.info(f"\033[92m✓\033[0m Sistem proxy ayarlandı: \033[1m{svc}\033[0m → 127.0.0.1:{self.port}")

            return True

        except subprocess.CalledProcessError as e:
            log.error(f"Proxy ayarı başarısız: {e}")
            return False

    def restore(self):
        """Sistem proxy'sini eski haline getir."""
        for svc in self._services:
            try:
                # Proxy'leri kapat
                subprocess.run([
                    'networksetup', '-setwebproxystate', svc, 'off'
                ], capture_output=True)
                subprocess.run([
                    'networksetup', '-setsecurewebproxystate', svc, 'off'
                ], capture_output=True)

                log.info(f"\033[92m✓\033[0m Sistem proxy geri yüklendi: \033[1m{svc}\033[0m")
            except:
                pass

    def _save_current_settings(self, service: str):
        """Mevcut proxy ayarlarını kaydet."""
        try:
            result = subprocess.run(
                ['networksetup', '-getwebproxy', service],
                capture_output=True, text=True
            )
            self._original_settings[service] = result.stdout
        except:
            pass


# ═══════════════════════════════════════════════════════════════
# İstatistik Gösterimi
# ═══════════════════════════════════════════════════════════════

def format_stats(stats: dict) -> str:
    """İstatistikleri formatla."""
    uptime = int(time.time() - stats['start_time'])
    h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60

    return (
        f"\r\033[90m"
        f"[{h:02d}:{m:02d}:{s:02d}] "
        f"Toplam: {stats['total']} | "
        f"HTTPS: {stats['https']} | "
        f"HTTP: {stats['http']} | "
        f"Aktif: {stats['active']} | "
        f"Hata: {stats['errors']} | "
        f"DNS\u2197: {stats['dns_bypass']}"
        f"\033[0m"
    )


# ═══════════════════════════════════════════════════════════════
# Discord Bağlantı Testi
# ═══════════════════════════════════════════════════════════════

def _build_test_client_hello(hostname: str) -> bytes:
    """Test için minimal TLS ClientHello oluştur."""
    sni = hostname.encode() if isinstance(hostname, str) else hostname
    sni_ext = (
        b'\x00\x00'
        + struct.pack('!H', len(sni) + 5)
        + struct.pack('!H', len(sni) + 3)
        + b'\x00'
        + struct.pack('!H', len(sni))
        + sni
    )
    extensions = struct.pack('!H', len(sni_ext)) + sni_ext

    body = (
        b'\x03\x03'
        + os.urandom(32)
        + b'\x00'
        + b'\x00\x02\x00\xff'
        + b'\x01\x00'
        + extensions
    )

    handshake = b'\x01' + struct.pack('!I', len(body))[1:] + body
    record = b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake
    return record


async def test_discord_bypass(bypass: DPIBypass, use_dns: bool = True):
    """Discord'a GERÇEK TLS handshake ile bağlantı testi yap.
    ssl.MemoryBIO ile OpenSSL'in ürettiği gerçek ClientHello kullanır.
    """
    log.info("\033[93m⏳ Discord bağlantı testi yapılıyor...\033[0m")

    test_hosts = ['discord.com', 'gateway.discord.gg']
    success_count = 0

    for host in test_hosts:
        try:
            # DNS çözümle
            if use_dns:
                ip = await SecureDNS.resolve(host)
            else:
                try:
                    loop = asyncio.get_event_loop()
                    result = await loop.getaddrinfo(host, None, socket.AF_INET)
                    ip = result[0][4][0] if result else None
                except Exception:
                    ip = None

            if not ip:
                log.warning(f"  \033[91m❌ {host} — DNS çözümlenemedi\033[0m")
                continue

            log.info(f"  \033[90m→ {host} ({ip}) test ediliyor...\033[0m")

            # ═══ GERÇEK ClientHello oluştur (ssl.MemoryBIO) ═══
            # Python'un ssl modülü (OpenSSL) gerçek bir ClientHello üretir.
            # Doğru cipher suite'ler, extension'lar, TLS 1.3 desteği — sunucu kabul eder.
            ctx = ssl.create_default_context()
            in_bio = ssl.MemoryBIO()
            out_bio = ssl.MemoryBIO()
            sslobj = ctx.wrap_bio(
                in_bio, out_bio,
                server_side=False,
                server_hostname=host
            )
            try:
                sslobj.do_handshake()
            except ssl.SSLWantReadError:
                pass

            client_hello = out_bio.read()
            if not client_hello or len(client_hello) < 10:
                log.warning(f"  \033[91m❌ {host} — ClientHello oluşturulamadı\033[0m")
                continue

            # TCP bağlantı
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443),
                timeout=10
            )

            # DPI bypass ile ClientHello gönder
            sent = await bypass.process_tls_data(writer, client_hello)

            if sent:
                # ServerHello bekle (8 saniye — DPI timeout'u için yeterli)
                try:
                    resp = await asyncio.wait_for(reader.read(5), timeout=20)
                    if resp and len(resp) >= 1 and resp[0] == 0x16:
                        log.info(
                            f"  \033[92m✅ {host} ({ip}) — "
                            f"TLS ServerHello alındı! Bypass çalışıyor.\033[0m"
                        )
                        success_count += 1
                    elif resp:
                        log.warning(
                            f"  \033[91m❌ {host} — Beklenmeyen yanıt "
                            f"(0x{resp[0]:02x}, {len(resp)}B)\033[0m"
                        )
                    else:
                        log.warning(
                            f"  \033[91m❌ {host} — Bağlantı kesildi "
                            f"(DPI engeli!)\033[0m"
                        )
                except asyncio.TimeoutError:
                    log.warning(
                        f"  \033[91m❌ {host} — 20s yanıt yok "
                        f"(DPI paket düşürüyor)\033[0m"
                    )

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        except (OSError, asyncio.TimeoutError) as e:
            log.warning(f"  \033[91m❌ {host} — {e}\033[0m")
        except Exception as e:
            log.warning(f"  \033[91m❌ {host} — {type(e).__name__}: {e}\033[0m")

    if success_count == len(test_hosts):
        log.info(
            "\033[92m✅ Tüm testler başarılı! "
            "Discord DPI bypass çalışıyor.\033[0m\n"
        )
    elif success_count > 0:
        log.warning(
            f"\033[93m⚠️ {success_count}/{len(test_hosts)} test başarılı. "
            f"Kısmen çalışıyor.\033[0m\n"
        )
    else:
        log.warning(
            "\033[91m❌ Hiçbir test başarılı değil! "
            "DPI bypass çalışmıyor.\033[0m"
        )
        log.warning(
            "\033[93m   Deneyin: -7 veya "
            "--oob --fragment-delay 0.1\033[0m\n"
        )

    return success_count > 0


# ═══════════════════════════════════════════════════════════════
# Ana Program
# ═══════════════════════════════════════════════════════════════

def print_banner(strategy_id: int, strategy: dict, port: int,
                 use_dns: bool = True):
    """Başlangıç banner'ı."""
    print(f"""
\033[1;95m╔══════════════════════════════════════════════╗
║         ForMacDPI v{VERSION}              ║
║     macOS DPI Bypass Tool                    ║
╚══════════════════════════════════════════════╝\033[0m

  \033[1mStrateji {strategy_id}:\033[0m {strategy['name']}

  \033[90m┌─ Teknikler ──────────────────────────────────
  │ TCP_NOPUSH Flush:  ✅  \033[33m(macOS kesin segment ayrımı)\033[90m
  │ OOB Desync:        {'✅ Prefix (veri öncesi)' if strategy.get('oob_mode') == 'prefix' else '✅ SNI Ortası' if strategy.get('oob_mode') == 'mid' else '✅ Klasik (SNI başı)' if strategy.get('use_oob') else '❌'}
  │ TLS Record Split:  {'✅ (' + str(strategy.get('num_tls_records', 2)) + ' record)' if strategy.get('tls_record_split') else '❌ (sadece TCP)'}
  │ Çoklu Segment:     {'✅ (3 parça)' if strategy['extra_split'] else '❌ (2 parça)'}
  │ HTTP Parçalama:    {'✅' if strategy['split_http'] else '❌'}
  │ Host Karışık Harf: {'✅' if strategy['mix_host_case'] else '❌'}
  │ Sahte Paket:       {'✅ (TTL=' + str(strategy['fake_ttl']) + ')' if strategy['fake_packet'] else '❌'}
  │ DNS-over-HTTPS:    {'✅ (DoH + UDP fallback)' if use_dns else '❌'}
  │ Fragment Gecikme:  {int(strategy['fragment_delay']*1000)}ms
  └────────────────────────────────────────────\033[0m

  \033[90mPort: {port} | Ctrl+C ile durdur\033[0m
  \033[90mMod: {'Sadece engelli siteler (--only-blocked)' if strategy.get('_only_blocked') else 'Tüm trafik'}\033[0m
""")


def parse_args():
    """Komut satırı argümanlarını ayrıştır."""
    parser = argparse.ArgumentParser(
        description='ForMacDPI — macOS DPI Bypass Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Strateji Örnekleri:
  -1   Temel SNI parçalama (varsayılan)
  -2   SNI + Host karışık harf
  -3   SNI çoklu parçalama (3 segment)
  -4   SNI + sahte paket (TTL trick)
  -5   Tam agresif (tüm teknikler)
  -6   🇹🇷 Türkiye v1 — klasik OOB Desync
  -7   🇹🇷 Türkiye v1 alt — OOB + Record Split
  -8   🇹🇷 Türkiye v2 — OOB Prefix (ÖNERİLEN)
  -9   🇹🇷 Türkiye v3 — OOB SNI Ortası + Records

Örnekler:
  sudo python3 formacdpi.py -8         # Türkiye v2 — ÖNERİLEN
  sudo python3 formacdpi.py -9         # Türkiye v3 — alternatif
  sudo python3 formacdpi.py -6         # Türkiye v1 — eski mod
  sudo python3 formacdpi.py -5         # Agresif mod
  sudo python3 formacdpi.py --no-dns   # Güvenli DNS'i kapat
  python3 formacdpi.py --no-auto-proxy # Proxy elle ayarlanır
"""
    )

    # Strateji seçimi
    strat_group = parser.add_mutually_exclusive_group()
    for i in range(1, 10):
        strat_group.add_argument(
            f'-{i}', dest='strategy', action='store_const', const=i,
            help=f"Strateji {i}: {STRATEGIES[i]['name']}"
        )

    parser.add_argument('--port', '-p', type=int, default=DEFAULT_PORT,
                        help=f'Proxy port (varsayılan: {DEFAULT_PORT})')
    parser.add_argument('--bind', '-b', default='127.0.0.1',
                        help='Bağlanma adresi (varsayılan: 127.0.0.1)')
    parser.add_argument('--no-auto-proxy', action='store_true',
                        help='Sistem proxy ayarını otomatik yapma')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Detaylı log (her bağlantı gösterilir)')
    parser.add_argument('--debug', action='store_true',
                        help='Debug seviyesi log')
    parser.add_argument('--fragment-size', type=int,
                        help='Fragment boyutu (byte, minimum 1)')
    parser.add_argument('--no-fake', action='store_true',
                        help='Sahte paket gönderimini devre dışı bırak')
    parser.add_argument('--fake-ttl', type=int,
                        help='Sahte paket TTL değeri')
    parser.add_argument('--no-dns', action='store_true',
                        help='Güvenli DNS çözümlemesini kapat')
    parser.add_argument('--record-split', action='store_true',
                        help='TLS record splitting aktif et (varsayılan: kapalı)')
    parser.add_argument('--fragment-delay', type=float,
                        help='Fragment arası gecikme (saniye, ör: 0.25)')
    parser.add_argument('--no-test', action='store_true',
                        help='Başlangıç bağlantı testini atla')
    parser.add_argument('--oob', action='store_true',
                        help='TCP OOB (Out-of-Band) desync aktif et')
    parser.add_argument('--only-blocked', action='store_true', default=True,
                        help='Sadece engelli sitelere bypass uygula (varsayılan: açık)')
    parser.add_argument('--all-traffic', action='store_true',
                        help='Tüm trafiğe bypass uygula (yavaşlatır)')
    parser.add_argument('--version', action='version',
                        version=f'ForMacDPI {VERSION}')

    args = parser.parse_args()

    if args.strategy is None:
        args.strategy = 1

    return args


async def stats_printer(proxy: ProxyServer):
    """Periyodik istatistik yazdırıcı."""
    while True:
        await asyncio.sleep(5)
        line = format_stats(proxy.stats)
        sys.stderr.write(line)
        sys.stderr.flush()


async def main():
    """Ana program."""
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Strateji yükle
    strategy = dict(STRATEGIES[args.strategy])

    # Argüman override'ları
    if args.fragment_size:
        if args.fragment_size < 1:
            print("Hata: --fragment-size en az 1 olmalıdır.", file=sys.stderr)
            sys.exit(1)
        strategy['fragment_size'] = args.fragment_size
    if args.no_fake:
        strategy['fake_packet'] = False
    if args.fake_ttl:
        strategy['fake_ttl'] = args.fake_ttl
    if args.record_split:
        strategy['tls_record_split'] = True
    if args.fragment_delay is not None:
        strategy['fragment_delay'] = args.fragment_delay
    if args.oob:
        strategy['use_oob'] = True

    # --all-traffic varsa only_blocked'ı kapat
    if args.all_traffic:
        args.only_blocked = False

    use_dns = not args.no_dns

    # Banner (only_blocked bilgisi ekle)
    strategy['_only_blocked'] = args.only_blocked
    print_banner(args.strategy, strategy, args.port, use_dns)
    del strategy['_only_blocked']  # DPIBypass'a geçmesin

    if args.only_blocked:
        log.info(
            f"\033[92m✓\033[0m Akıllı mod: sadece "
            f"\033[1m{len(BLOCKED_DOMAINS)} engelli site\033[0m → DPI bypass, "
            f"diğerleri direkt geçer (hız kaybı SIFIR)"
        )
    else:
        log.info(
            f"\033[93m⚠\033[0m Tüm trafik modu: her site DPI bypass'tan geçer "
            f"(--only-blocked ile daha hızlı)"
        )

    # DPI bypass motoru
    bypass = DPIBypass(strategy)

    # Proxy sunucusu
    proxy = ProxyServer(
        bypass=bypass,
        bind_addr=args.bind,
        port=args.port,
        verbose=args.verbose or args.debug,
        use_secure_dns=use_dns,
        only_blocked=args.only_blocked
    )

    # macOS proxy yönetimi
    mac_proxy = None
    if not args.no_auto_proxy:
        mac_proxy = MacOSProxy(args.port)
        if not mac_proxy.setup():
            log.warning("Otomatik proxy ayarlanamadı. Elle ayarlayın:")
            log.warning(f"  Sistem Tercihleri → Ağ → Proxy → HTTP/HTTPS → 127.0.0.1:{args.port}")
            mac_proxy = None

    # Temizleme fonksiyonu
    cleanup_done = False
    stats_task = None

    async def cleanup():
        nonlocal cleanup_done, stats_task
        if cleanup_done:
            return
        cleanup_done = True

        log.info("\n\033[93mKapatılıyor...\033[0m")

        # İstatistik task'ını iptal et
        if stats_task and not stats_task.done():
            stats_task.cancel()
            try:
                await stats_task
            except asyncio.CancelledError:
                pass

        try:
            await asyncio.wait_for(proxy.stop(), timeout=5)
        except asyncio.TimeoutError:
            log.debug("Proxy kapatma zaman aşımı, zorla kapatma")
        if mac_proxy:
            mac_proxy.restore()
        # Son istatistikler
        stats = proxy.stats
        uptime = int(time.time() - stats['start_time'])
        log.info(
            f"\033[90mOturum: {uptime}s | "
            f"Toplam: {stats['total']} | "
            f"HTTPS: {stats['https']} | "
            f"HTTP: {stats['http']} | "
            f"Hata: {stats['errors']} | "
            f"DNS↗: {stats['dns_bypass']}\033[0m"
        )
        log.info("\033[92m✓ ForMacDPI kapatıldı.\033[0m")

    # Graceful shutdown event
    shutdown_event = asyncio.Event()

    # Signal handler
    loop = asyncio.get_event_loop()

    def signal_handler():
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    # Sunucuyu başlat
    try:
        await proxy.start()

        if use_dns:
            log.info(
                "\033[92m✓\033[0m Güvenli DNS aktif: "
                "\033[1mDoH (HTTPS) + UDP fallback\033[0m"
            )

        # Başlangıç bağlantı testi
        if not args.no_test:
            await test_discord_bypass(bypass, use_dns)

        log.info("\033[92m✓ ForMacDPI çalışıyor. Ctrl+C ile durdurabilirsiniz.\033[0m\n")

        # İstatistik yazdırıcı
        stats_task = asyncio.create_task(stats_printer(proxy))

        # Signal gelene kadar bekle
        await shutdown_event.wait()

    except Exception as e:
        log.error(f"Sunucu hatası: {e}")
    finally:
        await cleanup()


if __name__ == '__main__':
    if sys.version_info < (3, 8):
        print("Python 3.8+ gerekli!", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
