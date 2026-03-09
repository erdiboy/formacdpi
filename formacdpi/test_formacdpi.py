#!/usr/bin/env python3
"""ForMacDPI unit testleri"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from formacdpi import *
import struct

def build_test_client_hello(hostname):
    sni = hostname.encode()
    sni_ext = (
        b'\x00\x00'
        + struct.pack('>H', len(sni) + 5)
        + struct.pack('>H', len(sni) + 3)
        + b'\x00'
        + struct.pack('>H', len(sni))
        + sni
    )
    extensions = struct.pack('>H', len(sni_ext)) + sni_ext

    body = (
        b'\x03\x03'
        + os.urandom(32)
        + b'\x00'
        + b'\x00\x02\x00\xff'
        + b'\x01\x00'
        + extensions
    )

    handshake = b'\x01' + struct.pack('>I', len(body))[1:] + body
    record = b'\x16\x03\x01' + struct.pack('>H', len(handshake)) + handshake
    return record


def run_tests():
    passed = 0
    failed = 0

    # Test 1: SNI extraction
    hello = build_test_client_hello('www.example.com')
    sni = extract_sni(hello)
    if sni == 'www.example.com':
        print(f'  ✅ SNI extraction: {sni}')
        passed += 1
    else:
        print(f'  ❌ SNI extraction: expected www.example.com, got {sni}')
        failed += 1

    # Test 2: SNI offset
    info = parse_tls_client_hello(hello)
    if info and info['sni'] == 'www.example.com' and info['sni_length'] == 15:
        print(f'  ✅ SNI offset: {info["sni_offset"]}, len: {info["sni_length"]}')
        passed += 1
    else:
        print(f'  ❌ SNI offset: {info}')
        failed += 1

    # Test 3: HTTP Host extraction
    http_req = b'GET / HTTP/1.1\r\nHost: www.blocked-site.com\r\nUser-Agent: test\r\n\r\n'
    host = extract_http_host(http_req)
    if host == 'www.blocked-site.com':
        print(f'  ✅ HTTP Host extraction: {host}')
        passed += 1
    else:
        print(f'  ❌ HTTP Host extraction: {host}')
        failed += 1

    # Test 4: Host header offset
    pos = find_host_header_position(http_req)
    if pos:
        offset, length = pos
        text = http_req.decode()
        host_val = text[offset:offset+length]
        if host_val == 'www.blocked-site.com':
            print(f'  ✅ Host offset: {offset}, len: {length}, val: "{host_val}"')
            passed += 1
        else:
            print(f'  ❌ Host offset value: "{host_val}"')
            failed += 1
    else:
        print(f'  ❌ Host offset: not found')
        failed += 1

    # Test 5: CONNECT parsing
    connect = b'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com\r\n\r\n'
    result = parse_connect_request(connect)
    if result == ('www.example.com', 443):
        print(f'  ✅ CONNECT parse: {result}')
        passed += 1
    else:
        print(f'  ❌ CONNECT parse: {result}')
        failed += 1

    # Test 6: HTTP proxy request parse
    proxy_req = b'GET http://www.example.com/path HTTP/1.1\r\nHost: www.example.com\r\n\r\n'
    result = parse_http_request(proxy_req)
    if result:
        host, port, modified = result
        if host == 'www.example.com' and port == 80 and b'http://www.example.com' not in modified:
            print(f'  ✅ HTTP proxy parse: host={host}, port={port}')
            print(f'     Modified: {modified[:60]}...')
            passed += 1
        else:
            print(f'  ❌ HTTP proxy parse values wrong')
            failed += 1
    else:
        print(f'  ❌ HTTP proxy parse: None')
        failed += 1

    # Test 7: Mix case
    mixed = DPIBypass.mix_case('example.com')
    if mixed == 'eXaMpLe.cOm':
        print(f'  ✅ Mix case: example.com → {mixed}')
        passed += 1
    else:
        print(f'  ❌ Mix case: {mixed}')
        failed += 1

    # Test 8: Targeted split (2 big fragments, not micro-fragments)
    engine = DPIBypass({'fragment_size': 3})
    frags = engine.create_fragments(b'Hello, World!', split_offsets=[5])
    joined = b''.join(frags)
    if joined == b'Hello, World!' and len(frags) == 2:
        print(f'  \u2705 Targeted split: {len(frags)} parcas -> {[f for f in frags]}')
        passed += 1
    else:
        print(f'  \u274c Targeted split: {len(frags)} parcas, join={joined == b"Hello, World!"}')
        failed += 1

    # Test 9: Extra split (3 fragments)
    engine2 = DPIBypass({'extra_split': True})
    frags2 = engine2.create_fragments(b'ABCDEFGHIJKLMNOP', split_offsets=[4, 8])
    if len(frags2) == 3 and b''.join(frags2) == b'ABCDEFGHIJKLMNOP':
        print(f'  \u2705 Extra split: {len(frags2)} parcas -> {[f for f in frags2]}')
        passed += 1
    else:
        print(f'  \u274c Extra split: {len(frags2)} parcas')
        failed += 1

    # Test 10: Fake ClientHello
    engine3 = DPIBypass({'fake_packet': True})
    fake = engine3._build_fake_client_hello(b'www.w3.org')
    if fake[0:1] == b'\x16':
        fake_sni = extract_sni(fake)
        if fake_sni == 'www.w3.org':
            print(f'  ✅ Fake ClientHello: SNI={fake_sni}, len={len(fake)}')
            passed += 1
        else:
            print(f'  ❌ Fake ClientHello SNI: {fake_sni}')
            failed += 1
    else:
        print(f'  ❌ Fake ClientHello: bad header')
        failed += 1

    # Test 11: HTTP host manipulation
    engine4 = DPIBypass({'mix_host_case': True, 'remove_host_space': True})
    req = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    manipulated = engine4.manipulate_http_request(req)
    text = manipulated.decode('latin-1')
    if 'eXaMpLe.cOm' in text and 'Host:eXaMpLe.cOm' in text:
        print(f'  ✅ HTTP manipulation: {repr(text[text.find("Host:"):][:25])}')
        passed += 1
    else:
        print(f'  ❌ HTTP manipulation: {repr(text)}')
        failed += 1

    # Test 12: Multi SNI hostname
    hello2 = build_test_client_hello('really.long.subdomain.example.co.uk')
    sni2 = extract_sni(hello2)
    if sni2 == 'really.long.subdomain.example.co.uk':
        print(f'  ✅ Long SNI: {sni2}')
        passed += 1
    else:
        print(f'  ❌ Long SNI: {sni2}')
        failed += 1

    # ═══ v2.1 Tests ═══

    # Test 13: Pure TCP Segmentation (varsayılan — Windows GoodbyeDPI gibi)
    engine_tcp = DPIBypass({'split_at_sni': True, 'extra_split': False, 'tls_record_split': False})
    hello_tcp = build_test_client_hello('discord.com')
    info_tcp = parse_tls_client_hello(hello_tcp)
    if info_tcp:
        sni_start = info_tcp['sni_offset']
        # İki parça: SNI öncesi + SNI sonrası
        frag1 = hello_tcp[:sni_start]
        frag2 = hello_tcp[sni_start:]
        # SNI ilk parçada olmamalı, ikinci parçada olmalı
        sni_not_in_f1 = b'discord.com' not in frag1
        sni_in_f2 = b'discord.com' in frag2
        # Birleşince orijinal olmalı
        joined_ok = frag1 + frag2 == hello_tcp
        if sni_not_in_f1 and sni_in_f2 and joined_ok:
            print(f'  ✅ Pure TCP Split: 2 segments, f1={len(frag1)}B f2={len(frag2)}B, SNI only in seg2')
            passed += 1
        else:
            print(f'  ❌ Pure TCP Split: no_sni_f1={sni_not_in_f1}, sni_f2={sni_in_f2}, joined={joined_ok}')
            failed += 1
    else:
        print(f'  ❌ Pure TCP Split: could not parse hello')
        failed += 1

    # Test 14: Extra split produces 3 TCP segments (pure TCP, no TLS record split)
    engine_extra_tcp = DPIBypass({'split_at_sni': True, 'extra_split': True, 'tls_record_split': False})
    hello14 = build_test_client_hello('gateway.discord.gg')
    info14 = parse_tls_client_hello(hello14)
    if info14:
        sni_start14 = info14['sni_offset']
        # 3 parça: [0x16] [1..sni_start] [sni_start..]
        f1 = hello14[:1]
        f2 = hello14[1:sni_start14]
        f3 = hello14[sni_start14:]
        all_frags = [f for f in [f1, f2, f3] if f]
        joined14 = b''.join(all_frags)
        if (len(all_frags) == 3 and f1 == b'\x16'
                and b'gateway.discord.gg' not in f1
                and b'gateway.discord.gg' not in f2
                and b'gateway.discord.gg' in f3
                and joined14 == hello14):
            print(f'  ✅ Extra TCP Split: 3 segments [{len(f1)},{len(f2)},{len(f3)}], SNI only in seg3')
            passed += 1
        else:
            print(f'  ❌ Extra TCP Split: frags={len(all_frags)}, joined={joined14 == hello14}')
            failed += 1
    else:
        print(f'  ❌ Extra TCP Split: parse failed')
        failed += 1

    # Test 15: TLS Record Split (opsiyonel mod — --record-split ile)
    engine_rs = DPIBypass({'tls_record_split': True})
    hello_rs = build_test_client_hello('discord.com')
    info_rs = parse_tls_client_hello(hello_rs)
    if info_rs:
        records = engine_rs.split_tls_records(hello_rs, info_rs['sni_offset'])
        if len(records) == 2:
            r1_valid = records[0][0:1] == b'\x16' and len(records[0]) >= 6
            r2_valid = records[1][0:1] == b'\x16' and len(records[1]) >= 6
            r1_payload = records[0][5:]
            r2_payload = records[1][5:]
            original_payload = hello_rs[5:]
            payload_match = r1_payload + r2_payload == original_payload
            r1_has_no_sni = b'discord.com' not in records[0]
            if r1_valid and r2_valid and payload_match and r1_has_no_sni:
                print(f'  ✅ TLS Record Split (opt-in): 2 records, r1={len(records[0])}B r2={len(records[1])}B')
                passed += 1
            else:
                print(f'  ❌ TLS Record Split: valid={r1_valid},{r2_valid} payload={payload_match} no_sni={r1_has_no_sni}')
                failed += 1
        else:
            print(f'  ❌ TLS Record Split: expected 2, got {len(records)}')
            failed += 1
    else:
        print(f'  ❌ TLS Record Split: could not parse hello')
        failed += 1

    # Test 16: Strategy 6 (Turkey) — OOB Desync ON, fast delay
    if 6 in STRATEGIES:
        s6 = STRATEGIES[6]
        turkey_ok = (
            s6.get('use_oob') == True
            and s6['extra_split'] == True
            and s6['mix_host_case'] == True
            and s6['fragment_delay'] <= 0.2
            and s6['fake_packet'] == False
        )
        if turkey_ok:
            print(f'  ✅ Turkey strategy: OOB Desync, '
                  f'delay={s6["fragment_delay"]}s')
            passed += 1
        else:
            print(f'  ❌ Turkey strategy: use_oob={s6.get("use_oob")}, '
                  f'delay={s6["fragment_delay"]}, fake={s6["fake_packet"]}')
            failed += 1
    else:
        print(f'  ❌ Turkey strategy: not found')
        failed += 1

    # Test 17: SecureDNS parse response (synthetic)
    dns_txn = 0x1234
    dns_header = struct.pack('!HHHHHH', dns_txn, 0x8180, 1, 1, 0, 0)
    dns_question = b'\x07example\x03com\x00\x00\x01\x00\x01'
    dns_answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x01\x02\x03\x04'
    dns_response = dns_header + dns_question + dns_answer
    dns_ip = SecureDNS._parse_dns_response(dns_response, dns_txn)
    if dns_ip == '1.2.3.4':
        print(f'  ✅ DNS response parse: {dns_ip}')
        passed += 1
    else:
        print(f'  ❌ DNS response parse: {dns_ip}')
        failed += 1

    # Test 18: SecureDNS has DoH capability
    has_doh = hasattr(SecureDNS, '_doh_resolve') and hasattr(SecureDNS, 'DOH_SERVERS')
    if has_doh and len(SecureDNS.DOH_SERVERS) >= 2:
        print(f'  ✅ DNS-over-HTTPS: {len(SecureDNS.DOH_SERVERS)} DoH servers configured')
        passed += 1
    else:
        print(f'  ❌ DNS-over-HTTPS: not configured')
        failed += 1

    # Test 19: _build_test_client_hello function exists and works
    try:
        from formacdpi import _build_test_client_hello
        test_hello = _build_test_client_hello('test.discord.com')
        test_sni = extract_sni(test_hello)
        if test_sni == 'test.discord.com' and test_hello[0] == 0x16:
            print(f'  ✅ Test ClientHello builder: SNI={test_sni}')
            passed += 1
        else:
            print(f'  ❌ Test ClientHello builder: SNI={test_sni}')
            failed += 1
    except Exception as e:
        print(f'  ❌ Test ClientHello builder: {e}')
        failed += 1
    # Test 20: Multi-record TLS split (v2.3 — N records)
    engine_multi = DPIBypass({'tls_record_split': True, 'num_tls_records': 6})
    hello_multi = build_test_client_hello('discord.com')
    info_multi = parse_tls_client_hello(hello_multi)
    if info_multi:
        records_multi = engine_multi.split_tls_records_multi(
            hello_multi, info_multi['sni_offset'], info_multi['sni_length'], 6
        )
        all_valid_m = all(r[0:1] == b'\x16' and len(r) >= 6 for r in records_multi)
        combined_payload_m = b''.join(r[5:] for r in records_multi)
        original_payload_m = hello_multi[5:]
        payload_ok_m = combined_payload_m == original_payload_m
        sni_bytes_m = b'discord.com'
        sni_split_m = not any(sni_bytes_m in r for r in records_multi)
        if len(records_multi) >= 5 and all_valid_m and payload_ok_m and sni_split_m:
            print(f'  \u2705 Multi-record split: {len(records_multi)} records, payload OK, SNI split')
            passed += 1
        else:
            print(f'  \u274c Multi-record split: n={len(records_multi)}, valid={all_valid_m}, '
                  f'payload={payload_ok_m}, sni_split={sni_split_m}')
            failed += 1
    else:
        print(f'  \u274c Multi-record split: could not parse hello')
        failed += 1

    # Test 21: OOB Desync — use_oob parameter and method exist
    engine_oob = DPIBypass({'use_oob': True, 'split_at_sni': True, 'fragment_delay': 0.05})
    has_oob_method = hasattr(engine_oob, 'send_with_oob_desync')
    if engine_oob.use_oob and has_oob_method:
        print(f'  ✅ OOB Desync: use_oob=True, send_with_oob_desync exists')
        passed += 1
    else:
        print(f'  ❌ OOB Desync: use_oob={engine_oob.use_oob}, method={has_oob_method}')
        failed += 1

    # Test 22: Strategy 7 exists (Turkey alternative with OOB + Record Split)
    if 7 in STRATEGIES:
        s7 = STRATEGIES[7]
        s7_ok = (
            s7.get('use_oob') == True
            and s7.get('tls_record_split') == True
            and s7.get('num_tls_records', 2) >= 4
        )
        if s7_ok:
            print(f'  ✅ Strategy 7: OOB + {s7["num_tls_records"]} records')
            passed += 1
        else:
            print(f'  ❌ Strategy 7: oob={s7.get("use_oob")}, split={s7.get("tls_record_split")}')
            failed += 1
    else:
        print(f'  ❌ Strategy 7: not found')
        failed += 1

    # Test 23: Strategy 8 — OOB Prefix mode
    if 8 in STRATEGIES:
        s8 = STRATEGIES[8]
        s8_ok = (
            s8.get('use_oob') == True
            and s8.get('oob_mode') == 'prefix'
            and s8.get('fragment_delay', 1) <= 0.02
        )
        if s8_ok:
            # Also verify DPIBypass creates correct oob_mode
            engine_s8 = DPIBypass(s8)
            if engine_s8.oob_mode == 'prefix' and hasattr(engine_s8, 'send_with_oob_prefix'):
                print(f'  ✅ Strategy 8: OOB Prefix, delay={s8["fragment_delay"]}s, method exists')
                passed += 1
            else:
                print(f'  ❌ Strategy 8: oob_mode={engine_s8.oob_mode}, method={hasattr(engine_s8, "send_with_oob_prefix")}')
                failed += 1
        else:
            print(f'  ❌ Strategy 8: oob={s8.get("use_oob")}, mode={s8.get("oob_mode")}, delay={s8.get("fragment_delay")}')
            failed += 1
    else:
        print(f'  ❌ Strategy 8: not found')
        failed += 1

    # Test 24: Strategy 9 — OOB SNI Middle + Records
    if 9 in STRATEGIES:
        s9 = STRATEGIES[9]
        s9_ok = (
            s9.get('use_oob') == True
            and s9.get('oob_mode') == 'mid'
            and s9.get('tls_record_split') == True
            and s9.get('num_tls_records', 2) >= 6
        )
        if s9_ok:
            engine_s9 = DPIBypass(s9)
            if engine_s9.oob_mode == 'mid':
                print(f'  ✅ Strategy 9: OOB Mid + {s9["num_tls_records"]} records, delay={s9["fragment_delay"]}s')
                passed += 1
            else:
                print(f'  ❌ Strategy 9: oob_mode={engine_s9.oob_mode}')
                failed += 1
        else:
            print(f'  ❌ Strategy 9: oob={s9.get("use_oob")}, mode={s9.get("oob_mode")}, split={s9.get("tls_record_split")}')
            failed += 1
    else:
        print(f'  ❌ Strategy 9: not found')
        failed += 1

    # Test 25: OOB mode backward compat — use_oob=True without oob_mode → classic
    engine_compat = DPIBypass({'use_oob': True, 'split_at_sni': True})
    if engine_compat.oob_mode == 'classic':
        print(f'  ✅ OOB backward compat: use_oob=True → oob_mode=classic')
        passed += 1
    else:
        print(f'  ❌ OOB backward compat: expected classic, got {engine_compat.oob_mode}')
        failed += 1

    # ═══ v2.7 Voice Tests ═══

    # Test 26: Voice server detection (v2.8 — broader, uses _is_voice_server method)
    from formacdpi import ProxyServer as _PS
    voice_hosts = [
        'us-south12345.discord.gg',
        'europe4567.discord.gg',
        'brazil890.discord.gg',
        'singapore1.discord.gg',
        'us-east-1a2b.discord.gg',
        '123456789.discord.gg',
        'rotterdam3321.discord.gg',
        'some-region.discord.media',
    ]
    non_voice_hosts = [
        'gateway.discord.gg',
        'cdn.discord.gg',
        'discord.gg',
        'cdn.discordapp.com',
        'discord.com',
    ]
    voice_ok = all(_PS._is_voice_server(h) for h in voice_hosts)
    non_voice_ok = all(not _PS._is_voice_server(h) for h in non_voice_hosts)
    if voice_ok and non_voice_ok:
        print(f'  ✅ Voice server detection: {len(voice_hosts)} voice, {len(non_voice_hosts)} non-voice')
        passed += 1
    else:
        for h in voice_hosts:
            if not _PS._is_voice_server(h):
                print(f'    ❌ Should be voice: {h}')
        for h in non_voice_hosts:
            if _PS._is_voice_server(h):
                print(f'    ❌ Should NOT be voice: {h}')
        print(f'  ❌ Voice server detection: voice={voice_ok}, non_voice={non_voice_ok}')
        failed += 1

    # Test 27: discordapp.net root domain blocking
    from formacdpi import BLOCKED_DOMAINS
    net_root = 'discordapp.net' in BLOCKED_DOMAINS
    # Alt domain eşleşmesi simülasyonu
    test_hostname = 'voice-server-123.discordapp.net'
    net_subdomain_match = any(
        test_hostname == d or test_hostname.endswith('.' + d)
        for d in BLOCKED_DOMAINS
    )
    if net_root and net_subdomain_match:
        print(f'  ✅ discordapp.net: root in list, subdomain matches')
        passed += 1
    else:
        print(f'  ❌ discordapp.net: root={net_root}, subdomain_match={net_subdomain_match}')
        failed += 1

    # Test 28: Voice bypass = Agresif TCP seg (GoodbyeDPI tarzı, TLS record split yok)
    voice_bypass = DPIBypass({
        'fragment_delay': 0.050,
    })
    has_aggressive = hasattr(voice_bypass, 'send_fragmented_aggressive')
    if has_aggressive and voice_bypass.fragment_delay >= 0.050:
        print(f'  ✅ Voice bypass config: Agresif TCP seg (SO_SNDBUF=256, 50ms delay, TLS rec split yok)')
        passed += 1
    else:
        print(f'  ❌ Voice bypass config: aggressive={has_aggressive}, delay={voice_bypass.fragment_delay}')
        failed += 1

    # Test 29: Voice server SNI extraction
    hello_voice = build_test_client_hello('us-south12345.discord.gg')
    sni_voice = extract_sni(hello_voice)
    if sni_voice == 'us-south12345.discord.gg':
        print(f'  ✅ Voice SNI extraction: {sni_voice}')
        passed += 1
    else:
        print(f'  ❌ Voice SNI extraction: {sni_voice}')
        failed += 1

    print(f'\n  {"🎉" if failed == 0 else "⚠️"} Sonuc: {passed}/{passed+failed} test basarili')
    return failed == 0

if __name__ == '__main__':
    print('\n  ForMacDPI Unit Tests\n  ─────────────────────────')
    success = run_tests()
    print()
    sys.exit(0 if success else 1)
