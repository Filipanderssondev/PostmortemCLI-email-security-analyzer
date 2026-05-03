# tests/test_parser.py

from email import message_from_string
from src.parser import parse_email, extract_urls, decode_subject


def test_parse_basic_headers():
    raw = """From: attacker@evil.com
To: victim@smhi.se
Subject: Test
Date: Mon, 01 Jan 2026 12:00:00 +0000
Message-ID: <test123@evil.com>
Content-Type: text/plain

Hello world
"""
    message = message_from_string(raw)
    parsed  = parse_email(message)

    assert parsed["headers"]["from"]    == "attacker@evil.com"
    assert parsed["headers"]["to"]      == "victim@smhi.se"
    assert parsed["headers"]["subject"] == "Test"


def test_extract_urls():
    text = "Click here: http://evil.ru/malware.exe and http://phishing.com"
    urls = extract_urls(text)

    assert "http://evil.ru/malware.exe" in urls
    assert "http://phishing.com" in urls


def test_no_urls():
    parsed = extract_urls("")
    assert parsed == []


def test_empty_subject():
    assert decode_subject("") == ""