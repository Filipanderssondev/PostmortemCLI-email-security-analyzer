import pytest
from email import message_from_bytes
from src.parser import parse_email, decode_subject, extract_urls
from tests.conftest import (
    CLEAN_EML, PHISHING_EML, ATTACHMENT_EML, MALWARE_EML,
)


# ── decode_subject ────────────────────────────────────────────────────────────

class TestDecodeSubject:
    def test_plain_ascii(self):
        assert decode_subject("Hello World") == "Hello World"

    def test_encoded_utf8_q(self):
        # =?UTF-8?Q?Br=C3=A4dskande=20fr=C3=A5ga?= → "Brädskande fråga"
        raw = "=?UTF-8?Q?Br=C3=A4dskande=20fr=C3=A5ga?="
        result = decode_subject(raw)
        assert "dskande" in result
        assert result != raw

    def test_encoded_utf8_b64(self):
        # =?UTF-8?B?SGVsbG8gV29ybGQ=?= → "Hello World"
        raw = "=?UTF-8?B?SGVsbG8gV29ybGQ=?="
        assert decode_subject(raw) == "Hello World"

    def test_empty_string(self):
        assert decode_subject("") == ""

    def test_none(self):
        assert decode_subject(None) == ""

    def test_plain_swedish(self):
        assert decode_subject("Brädskande ärende") == "Brädskande ärende"


# ── extract_urls ──────────────────────────────────────────────────────────────

class TestExtractUrls:
    def test_http_url(self):
        assert "http://example.com" in extract_urls("Visit http://example.com today")

    def test_https_url(self):
        assert "https://secure.com/path" in extract_urls("Go to https://secure.com/path now")

    def test_multiple_urls(self):
        text = "See https://a.com and http://b.com/page"
        urls = extract_urls(text)
        assert len(urls) == 2
        assert "https://a.com" in urls
        assert "http://b.com/page" in urls

    def test_no_urls(self):
        assert extract_urls("No links here at all.") == []

    def test_none_input(self):
        assert extract_urls(None) == []

    def test_empty_string(self):
        assert extract_urls("") == []

    def test_url_with_query_params(self):
        url = "https://evil.com/steal?token=abc&id=123"
        result = extract_urls(f"Click {url}")
        assert url in result

    def test_url_not_extracted_without_scheme(self):
        result = extract_urls("Visit example.com for more info")
        assert result == []


# ── parse_email ───────────────────────────────────────────────────────────────

class TestParseEmail:
    def test_basic_headers_extracted(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        h = parsed['headers']

        assert 'alice@legit.se' in h['from']
        assert 'bob@company.se' in h['to']
        assert h['subject'] == 'Meeting tomorrow'
        assert 'alice@legit.se' in h['reply_to']
        assert 'abc123@legit.se' in h['message_id']
        assert h['date'] != ''

    def test_new_headers_extracted(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        h = parsed['headers']

        assert 'alice@legit.se' in h['return_path']
        assert 'Apple Mail' in h['x_mailer']
        assert 'authentication_results' in h  # key must exist even if empty

    def test_received_chain_extracted(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        assert len(parsed['headers']['received']) >= 1
        assert '203.0.113.10' in parsed['headers']['received'][0]

    def test_body_text_extracted(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        assert 'meeting tomorrow' in parsed['body']['text'].lower()

    def test_body_html_extracted(self):
        msg = message_from_bytes(MALWARE_EML)
        parsed = parse_email(msg)
        assert '<html>' in parsed['body']['html'].lower()

    def test_url_extracted_from_body(self):
        msg = message_from_bytes(PHISHING_EML)
        parsed = parse_email(msg)
        assert any('evil-domain.com' in u for u in parsed['urls'])

    def test_url_extracted_from_html(self):
        msg = message_from_bytes(MALWARE_EML)
        parsed = parse_email(msg)
        assert any('phishing.example.com' in u for u in parsed['urls'])

    def test_urls_deduplicated(self):
        eml = b"""\
From: a@b.com\r\nTo: c@d.com\r\nSubject: x\r\n
Content-Type: text/plain\r\n\r\n
https://dup.com https://dup.com https://dup.com
"""
        msg = message_from_bytes(eml)
        parsed = parse_email(msg)
        assert parsed['urls'].count('https://dup.com') == 1

    def test_attachment_extracted(self):
        msg = message_from_bytes(ATTACHMENT_EML)
        parsed = parse_email(msg)
        assert len(parsed['attachments']) == 1
        att = parsed['attachments'][0]
        assert att['filename'] == 'invoice.exe'
        assert att['size'] > 0
        assert isinstance(att['data'], bytes)
        assert att['content_type'] != ''

    def test_no_attachments(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        assert parsed['attachments'] == []

    def test_no_urls(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        assert parsed['urls'] == []

    def test_return_keys_present(self):
        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        assert 'headers' in parsed
        assert 'body' in parsed
        assert 'attachments' in parsed
        assert 'urls' in parsed
        assert 'text' in parsed['body']
        assert 'html' in parsed['body']

    def test_missing_optional_headers_are_empty_strings(self):
        minimal = b"From: x@y.com\r\nTo: a@b.com\r\nSubject: test\r\n\r\nBody"
        msg = message_from_bytes(minimal)
        parsed = parse_email(msg)
        h = parsed['headers']
        assert h['reply_to'] == ''
        assert h['return_path'] == ''
        assert h['x_mailer'] == ''
        assert h['authentication_results'] == ''
        assert h['received'] == []