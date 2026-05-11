import sys
import os
import pytest
from email import message_from_bytes

# Ensure src/ is importable from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Raw .eml fixtures ─────────────────────────────────────────────────────────

CLEAN_EML = b"""\
From: Alice Smith <alice@legit.se>
To: bob@company.se
Subject: Meeting tomorrow
Reply-To: alice@legit.se
Return-Path: <alice@legit.se>
Message-ID: <abc123@legit.se>
Date: Mon, 1 Jan 2026 10:00:00 +0100
X-Mailer: Apple Mail
Received: from mx.legit.se (mx.legit.se [203.0.113.10]) by mx.company.se
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hi Bob, just confirming our meeting tomorrow at 10am.
"""

PHISHING_EML = b"""\
From: CEO <ceo@company.se>
To: finance@company.se
Subject: Urgent wire transfer
Reply-To: attacker@evil-domain.com
Return-Path: <bounce@evil-domain.com>
Message-ID: <xyz@other-domain.net>
Date: Mon, 1 Jan 2026 10:00:00 +0100
Received: from mail.evil.se (mail.evil.se [1.2.3.4]) by mx.company.se

Please wire $50,000 to account 12345 immediately.
Click here: http://evil-domain.com/steal?token=abc
"""

ATTACHMENT_EML = b"""\
From: sender@example.com
To: victim@company.se
Subject: Invoice
Reply-To: sender@example.com
Return-Path: <sender@example.com>
Message-ID: <msg@example.com>
Date: Mon, 1 Jan 2026 10:00:00 +0100
Received: from mx.example.com (mx.example.com [5.6.7.8]) by mx2.example.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Please find the invoice attached.
--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
--BOUNDARY--
"""

MALWARE_EML = b"""\
From: noreply@bank.se
To: customer@example.se
Subject: Your account
Reply-To: noreply@bank.se
Return-Path: <noreply@bank.se>
Message-ID: <id@bank.se>
Date: Mon, 1 Jan 2026 10:00:00 +0100
Received: from mx.bank.se (mx.bank.se [9.10.11.12]) by mx.example.se
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B2"

--B2
Content-Type: text/html

<html><body>Click <a href="https://phishing.example.com/login">here</a></body></html>
--B2
Content-Type: application/pdf
Content-Disposition: attachment; filename="statement.pdf.exe"
Content-Transfer-Encoding: base64

TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
--B2--
"""


@pytest.fixture
def clean_message():
    return message_from_bytes(CLEAN_EML), CLEAN_EML

@pytest.fixture
def phishing_message():
    return message_from_bytes(PHISHING_EML), PHISHING_EML

@pytest.fixture
def attachment_message():
    return message_from_bytes(ATTACHMENT_EML), ATTACHMENT_EML

@pytest.fixture
def malware_message():
    return message_from_bytes(MALWARE_EML), MALWARE_EML


# ── Analyzer fixture helpers ──────────────────────────────────────────────────

def make_header_findings(**overrides):
    base = {
        'from_domain':          'company.se',
        'reply_to_domain':      '',
        'return_path_domain':   '',
        'sender_ip':            '203.0.113.10',
        'received_hops':        1,
        'reply_mismatch':       False,
        'return_path_mismatch': False,
        'mid_mismatch':         False,
        'no_received':          False,
        'flags':                [],
    }
    base.update(overrides)
    return base


def make_auth_findings(spf='found', dmarc='found', dkim='found',
                       policy='reject', sig_present=False, sig_valid=None):
    return {
        'domain': 'company.se',
        'spf':    {'record': 'v=spf1 mx ~all', 'result': spf},
        'dmarc':  {'record': 'v=DMARC1; p=reject', 'result': dmarc, 'policy': policy},
        'dkim':   {'record': 'v=DKIM1; p=MIGf...', 'result': dkim,
                   'selector': 'mail', 'signature_present': sig_present,
                   'signature_valid': sig_valid},
        'flags':  [],
    }


def make_rep_findings(listed=False, threatfox=False, abuseipdb=-1):
    flags = []
    if listed:
        flags.append("Sender IP 203.0.113.10 listed on Spamhaus ZEN")
    if threatfox:
        flags.append("Sender IP 203.0.113.10 found in ThreatFox")
    if abuseipdb >= 80:
        flags.append(f"Sender IP 203.0.113.10 has AbuseIPDB confidence score {abuseipdb}/100")
    elif abuseipdb >= 25:
        flags.append(f"Sender IP 203.0.113.10 has elevated AbuseIPDB score {abuseipdb}/100")
    return {
        "ip":              "203.0.113.10",
        "spamhaus_zen":    listed,
        "threatfox_ip":    threatfox,
        "abuseipdb_score": abuseipdb,
        "flags":           flags,
    }


def make_url_findings(urlhaus=0, dbl=0, threatfox=0):
    return {
        "total": 0, "checked": 0, "results": [],
        "urlhaus_hits":   urlhaus,
        "dbl_hits":       dbl,
        "threatfox_hits": threatfox,
        "flags": [],
    }


def make_att_findings(mb_hits=0, tf_hits=0, results=None):
    return {
        "count": 0,
        "results":            results or [],
        "malwarebazaar_hits": mb_hits,
        "threatfox_hits":     tf_hits,
        "flags": [],
    }
