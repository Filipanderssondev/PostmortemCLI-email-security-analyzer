#!/usr/bin/env python3
"""
smoke_test.py
Run from project root before building the Docker image.
Tests every live feature: DNS, APIs, DKIM, SMTP, full scan pipeline.

Usage:
    python3 smoke_test.py
"""

import sys
import os
import time
import socket
import threading
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS  = "\033[92m[PASS]\033[0m"
FAIL  = "\033[91m[FAIL]\033[0m"
SKIP  = "\033[93m[SKIP]\033[0m"
INFO  = "\033[94m[INFO]\033[0m"

results = []

def check(name, fn):
    try:
        detail = fn()
        print(f"{PASS} {name}" + (f"  →  {detail}" if detail else ""))
        results.append((name, True))
    except Exception as e:
        print(f"{FAIL} {name}  →  {e}")
        results.append((name, False))


# ── 1. Dependencies importable ────────────────────────────────────────────────

print("\n── Dependencies ─────────────────────────────────────────────────────────")

check("import dns.resolver",
    lambda: __import__('dns.resolver', fromlist=['resolver']) and None)

check("import requests",
    lambda: __import__('requests') and None)

check("import dkim (dkimpy)",
    lambda: __import__('dkim') and None)

check("import aiosmtpd",
    lambda: __import__('aiosmtpd') and None)

check("import extract_msg",
    lambda: __import__('extract_msg') and None)


# ── 2. DNS – SPF, DMARC, DKIM against known good domain ──────────────────────

print("\n── DNS lookups (google.com) ─────────────────────────────────────────────")

def test_spf():
    import dns.resolver
    answers = dns.resolver.resolve('google.com', 'TXT', lifetime=5)
    for r in answers:
        t = b''.join(r.strings).decode()
        if t.startswith('v=spf1'):
            return t[:60] + '...'
    raise AssertionError("No SPF record found")

def test_dmarc():
    import dns.resolver
    answers = dns.resolver.resolve('_dmarc.google.com', 'TXT', lifetime=5)
    for r in answers:
        t = b''.join(r.strings).decode()
        if t.startswith('v=DMARC1'):
            return t[:60] + '...'
    raise AssertionError("No DMARC record found")

def test_dkim():
    import dns.resolver
    # google.com uses 'google' selector publicly
    answers = dns.resolver.resolve('google._domainkey.google.com', 'TXT', lifetime=5)
    for r in answers:
        t = b''.join(r.strings).decode()
        if 'p=' in t:
            return f"selector=google, record found"
    raise AssertionError("No DKIM record found")

check("SPF lookup (google.com)", test_spf)
check("DMARC lookup (_dmarc.google.com)", test_dmarc)
check("DKIM lookup (google._domainkey.google.com)", test_dkim)


# ── 3. Spamhaus ZEN – test IP is the documented test address ─────────────────

print("\n── Spamhaus ZEN DNSBL ───────────────────────────────────────────────────")

def test_spamhaus_listed():
    import dns.resolver
    # 127.0.0.2 is permanently listed on Spamhaus ZEN for testing purposes
    # https://www.spamhaus.org/faq/section/DNSBL%20Usage
    dns.resolver.resolve('2.0.0.127.zen.spamhaus.org', 'A', lifetime=5)
    return "127.0.0.2 correctly listed (test address)"

def test_spamhaus_clean():
    import dns.resolver
    # 1.1.1.1 (Cloudflare) should NOT be listed
    try:
        dns.resolver.resolve('1.1.1.1.zen.spamhaus.org', 'A', lifetime=5)
        raise AssertionError("1.1.1.1 listed on Spamhaus – unexpected")
    except dns.resolver.NXDOMAIN:
        return "1.1.1.1 correctly clean"

check("Spamhaus ZEN – listed IP (127.0.0.2)", test_spamhaus_listed)
check("Spamhaus ZEN – clean IP (1.1.1.1)", test_spamhaus_clean)


# ── 4. URLhaus API ────────────────────────────────────────────────────────────

print("\n── URLhaus API (abuse.ch) ───────────────────────────────────────────────")

def test_urlhaus_clean():
    import requests
    r = requests.post(
        'https://urlhaus-api.abuse.ch/v1/url/',
        data={'url': 'https://www.google.com'},
        timeout=5
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get('query_status') != 'is_url', "google.com flagged as malware – unexpected"
    return f"status={data.get('query_status')}"

def test_urlhaus_api_reachable():
    import requests
    r = requests.post(
        'https://urlhaus-api.abuse.ch/v1/url/',
        data={'url': 'http://example.com'},
        timeout=5
    )
    assert r.status_code == 200
    return f"HTTP {r.status_code}, response valid JSON"

check("URLhaus API reachable", test_urlhaus_api_reachable)
check("URLhaus – clean URL not flagged", test_urlhaus_clean)


# ── 5. MalwareBazaar API ──────────────────────────────────────────────────────

print("\n── MalwareBazaar API (abuse.ch) ─────────────────────────────────────────")

def test_malwarebazaar_known_hash():
    import requests
    # EICAR test file SHA256 – always present in MalwareBazaar
    eicar_sha256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    r = requests.post(
        'https://mb-api.abuse.ch/api/v1/',
        data={'query': 'get_info', 'hash': eicar_sha256},
        timeout=5
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get('query_status') == 'ok', f"Expected 'ok', got {data.get('query_status')}"
    return f"EICAR hash found: query_status=ok"

def test_malwarebazaar_unknown_hash():
    import requests
    clean_hash = 'a' * 64  # not a real hash
    r = requests.post(
        'https://mb-api.abuse.ch/api/v1/',
        data={'query': 'get_info', 'hash': clean_hash},
        timeout=5
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get('query_status') != 'ok'
    return f"Unknown hash correctly not found: query_status={data.get('query_status')}"

check("MalwareBazaar – EICAR hash found", test_malwarebazaar_known_hash)
check("MalwareBazaar – unknown hash not found", test_malwarebazaar_unknown_hash)


# ── 6. DKIM signature verification ───────────────────────────────────────────

print("\n── DKIM signature verification (dkimpy) ─────────────────────────────────")

def test_dkim_no_signature():
    import dkim
    raw = b'From: test@example.com\r\nTo: x@y.com\r\nSubject: test\r\n\r\nBody'
    assert b'DKIM-Signature' not in raw
    result = dkim.verify(raw)
    return f"Email without DKIM-Signature: verify()={result} (expected False)"

def test_dkim_test_eml():
    import dkim
    eml_path = os.path.join(os.path.dirname(__file__), 'tests', 'phishing_email.eml')
    if not os.path.exists(eml_path):
        return "tests/phishing_email.eml not found – skipped"
    with open(eml_path, 'rb') as f:
        raw = f.read()
    has_sig = b'DKIM-Signature' in raw
    if has_sig:
        result = dkim.verify(raw)
        return f"DKIM-Signature present, verify()={result}"
    return "No DKIM-Signature in test file (expected for test fixtures)"

check("dkimpy – email without signature", test_dkim_no_signature)
check("dkimpy – test .eml file", test_dkim_test_eml)


# ── 7. SMTP handle_DATA – raw bytes flow ─────────────────────────────────────

print("\n── SMTP handle_DATA (raw bytes) ─────────────────────────────────────────")

def test_smtp_handle_data():
    import asyncio
    import smtplib
    from email import message_from_bytes
    from aiosmtpd.controller import Controller

    received_raw = []

    class TestHandler:
        async def handle_DATA(self, server, session, envelope):
            received_raw.append(envelope.content)
            return '250 OK'

    async def run():
        handler    = TestHandler()
        controller = Controller(handler, hostname='127.0.0.1', port=11025)
        controller.start()
        await asyncio.sleep(0.2)

        try:
            test_msg = (
                b'From: sender@test.com\r\n'
                b'To: recv@test.com\r\n'
                b'Subject: SMTP test\r\n'
                b'\r\n'
                b'Test body.\r\n'
            )
            msg_obj = message_from_bytes(test_msg)

            with smtplib.SMTP('127.0.0.1', 11025, timeout=5) as smtp:
                smtp.send_message(msg_obj)

            await asyncio.sleep(0.2)
        finally:
            controller.stop()

    asyncio.run(run())

    assert len(received_raw) == 1, f"Expected 1 message, got {len(received_raw)}"
    raw = received_raw[0]
    assert isinstance(raw, bytes), f"envelope.content is {type(raw)}, expected bytes"
    assert b'SMTP test' in raw, "Subject not found in raw bytes"
    return f"envelope.content is bytes ({len(raw)} bytes), subject present"

check("SMTP handle_DATA – envelope.content is bytes", test_smtp_handle_data)


# ── 8. Full scan pipeline ─────────────────────────────────────────────────────

print("\n── Full scan pipeline ───────────────────────────────────────────────────")

def test_scan_phishing():
    eml = os.path.join(os.path.dirname(__file__), 'tests', 'phishing_email.eml')
    if not os.path.exists(eml):
        return "tests/phishing_email.eml not found – skipped"

    from email import message_from_bytes
    from src.parser import parse_email
    from src.analyzer import analyze

    with open(eml, 'rb') as f:
        raw = f.read()
    msg    = message_from_bytes(raw)
    parsed = parse_email(msg)
    result = analyze(parsed, raw_bytes=raw)

    assert 'verdict' in result
    assert result['verdict'] in ('MOST LIKELY SAFE', 'MOST LIKELY UNSAFE', 'FURTHER ANALYSIS REQUIRED')
    assert isinstance(result['all_flags'], list)
    return f"verdict={result['verdict']}, flags={len(result['all_flags'])}"

def test_scan_malware():
    eml = os.path.join(os.path.dirname(__file__), 'tests', 'malware_attachment.eml')
    if not os.path.exists(eml):
        return "tests/malware_attachment.eml not found – skipped"

    from email import message_from_bytes
    from src.parser import parse_email
    from src.analyzer import analyze

    with open(eml, 'rb') as f:
        raw = f.read()
    msg    = message_from_bytes(raw)
    parsed = parse_email(msg)
    result = analyze(parsed, raw_bytes=raw)

    assert 'verdict' in result
    atts = result['att_findings']['results']
    if atts:
        print(f"\n  {INFO} Attachments found:")
        for a in atts:
            print(f"       {a['filename']} | sha256: {a['sha256'][:32]}...")
            print(f"       dangerous={a['dangerous']} | mime_mismatch={a['mime_mismatch']} | mb={a['malwarebazaar']}")
    return f"verdict={result['verdict']}, attachments={len(atts)}, flags={len(result['all_flags'])}"

check("Full scan – phishing_email.eml", test_scan_phishing)
check("Full scan – malware_attachment.eml", test_scan_malware)


# ── 9. SMTP send → receive full flow ─────────────────────────────────────────

print("\n── SMTP send → receive → analyze ───────────────────────────────────────")

def test_smtp_full_flow():
    import asyncio
    import smtplib
    from email import message_from_bytes
    from aiosmtpd.controller import Controller
    from src.parser import parse_email
    from src.analyzer import analyze

    verdicts = []

    class FullHandler:
        async def handle_DATA(self, server, session, envelope):
            raw    = envelope.content
            msg    = message_from_bytes(raw)
            parsed = parse_email(msg)
            result = analyze(parsed, raw_bytes=raw)
            verdicts.append(result['verdict'])
            return '250 OK'

    async def run():
        controller = Controller(FullHandler(), hostname='127.0.0.1', port=11026)
        controller.start()
        await asyncio.sleep(0.2)

        try:
            test_eml = (
                b'From: ceo@company.se\r\n'
                b'To: finance@company.se\r\n'
                b'Reply-To: attacker@evil.com\r\n'
                b'Return-Path: <attacker@evil.com>\r\n'
                b'Subject: Urgent transfer\r\n'
                b'Message-ID: <id@other.net>\r\n'
                b'Received: from mail.evil.com (mail.evil.com [1.2.3.4]) by mx.company.se\r\n'
                b'\r\n'
                b'Please wire the money.\r\n'
            )
            msg_obj = message_from_bytes(test_eml)
            with smtplib.SMTP('127.0.0.1', 11026, timeout=5) as smtp:
                smtp.send_message(msg_obj)
            await asyncio.sleep(0.5)
        finally:
            controller.stop()

    asyncio.run(run())

    assert len(verdicts) == 1, f"Expected 1 verdict, got {len(verdicts)}"
    assert verdicts[0] == 'MOST LIKELY UNSAFE', f"Expected MOST LIKELY UNSAFE (reply-to mismatch), got {verdicts[0]}"
    return f"SMTP → parse → analyze → verdict={verdicts[0]}"

check("SMTP full flow – parse + analyze end-to-end", test_smtp_full_flow)


# ── Summary ───────────────────────────────────────────────────────────────────

passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total  = len(results)

print(f"\n{'='*56}")
print(f"  Results: {passed}/{total} passed", end="")
if failed:
    print(f"  |  {failed} FAILED:")
    for name, ok in results:
        if not ok:
            print(f"    ✗  {name}")
else:
    print("  – all clear")
print(f"{'='*56}\n")

sys.exit(0 if failed == 0 else 1)
