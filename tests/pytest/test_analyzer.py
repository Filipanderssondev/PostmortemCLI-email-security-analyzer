import os
import pytest
import dns.resolver
from unittest.mock import patch, MagicMock
from email import message_from_bytes

from src.analyzer import (
    _extract_domain, _extract_sender_ip, _sha256, _detect_mime,
    _PRIVATE_IP, _verify_dkim, _threatfox, _abuseipdb,
    DANGEROUS_EXTENSIONS, _ABUSEIPDB_MALICIOUS, _ABUSEIPDB_SUSPICIOUS,
    check_headers, check_authentication, check_reputation,
    check_urls, check_attachments, _calculate_verdict, analyze,
)
from tests.conftest import (
    CLEAN_EML, PHISHING_EML, ATTACHMENT_EML, MALWARE_EML,
    make_header_findings, make_auth_findings,
    make_rep_findings, make_url_findings, make_att_findings,
)
from src.parser import parse_email


# ── _extract_domain ───────────────────────────────────────────────────────────

class TestExtractDomain:
    def test_full_display_name(self):
        assert _extract_domain('Alice <alice@smhi.se>') == 'smhi.se'

    def test_bare_address(self):
        assert _extract_domain('noreply@google.com') == 'google.com'

    def test_angle_brackets_only(self):
        assert _extract_domain('<user@domain.org>') == 'domain.org'

    def test_empty_string(self):
        assert _extract_domain('') == ''

    def test_no_at_sign(self):
        assert _extract_domain('notanemail') == ''

    def test_uppercase_normalized(self):
        assert _extract_domain('User@DOMAIN.COM') == 'domain.com'

    def test_whitespace_stripped(self):
        assert _extract_domain('user@domain.se ') == 'domain.se'

    def test_subdomain(self):
        assert _extract_domain('user@mail.sub.domain.se') == 'mail.sub.domain.se'


# ── _extract_sender_ip ────────────────────────────────────────────────────────

class TestExtractSenderIp:
    def test_ip_in_brackets(self):
        received = ['from mx.evil.com (mx.evil.com [1.2.3.4]) by mx.example.com']
        assert _extract_sender_ip(received) == '1.2.3.4'

    def test_uses_last_element(self):
        received = [
            'from mx.relay.com (mx.relay.com [9.8.7.6]) by mx.dest.com',
            'from mx.origin.com (mx.origin.com [1.2.3.4]) by mx.relay.com',
        ]
        assert _extract_sender_ip(received) == '1.2.3.4'

    def test_empty_list(self):
        assert _extract_sender_ip([]) == ''

    def test_no_ip_in_header(self):
        assert _extract_sender_ip(['from mx.example.com by other.com']) == ''

    def test_valid_ip_formats(self):
        # Public IP in brackets — should be extracted
        received = ['from x ([89.144.44.2]) by y']
        assert _extract_sender_ip(received) == '89.144.44.2'

    def test_skips_private_ip(self):
        # Private/internal IPs must be skipped — we want the public sender
        received = ['from x ([192.168.1.255]) by y']
        assert _extract_sender_ip(received) == ''

    def test_matches_parenthesized_ip(self):
        # Real-world Received headers often use (parens), not [brackets]
        received = ['from mail.evil.com (89.144.44.2) by mx.example.com']
        assert _extract_sender_ip(received) == '89.144.44.2'


# ── _sha256 ───────────────────────────────────────────────────────────────────

class TestSha256:
    def test_known_hash(self):
        assert _sha256(b'') == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    def test_hello(self):
        assert _sha256(b'hello') == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

    def test_returns_64_chars(self):
        assert len(_sha256(b'anything')) == 64

    def test_different_data_different_hash(self):
        assert _sha256(b'aaa') != _sha256(b'bbb')




# ── _threatfox ────────────────────────────────────────────────────────────────

class TestThreatfox:
    @patch('src.analyzer.requests.post')
    def test_hit_returns_true(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'query_status': 'ok', 'data': [{'ioc': '1.2.3.4'}]}
        )
        assert _threatfox('1.2.3.4') == True

    @patch('src.analyzer.requests.post')
    def test_no_result_returns_false(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'query_status': 'no_result'}
        )
        assert _threatfox('clean.domain.com') == False

    @patch('src.analyzer.requests.post')
    def test_network_error_returns_false(self, mock_post):
        mock_post.side_effect = Exception('Timeout')
        assert _threatfox('1.2.3.4') == False

    def test_empty_string_returns_false(self):
        assert _threatfox('') == False

    @patch('src.analyzer.requests.post')
    def test_accepts_hash_ioc(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {'query_status': 'ok'}
        )
        sha256 = 'a' * 64
        result = _threatfox(sha256)
        assert result == True
        call_body = mock_post.call_args[1]['json']
        assert call_body['search_term'] == sha256

    @patch('src.analyzer.requests.post')
    def test_http_error_returns_false(self, mock_post):
        mock_post.return_value = MagicMock(status_code=429, json=lambda: {})
        assert _threatfox('1.2.3.4') == False


# ── _abuseipdb ────────────────────────────────────────────────────────────────

class TestAbuseipdb:
    def test_no_key_returns_minus_one(self):
        env = {k: v for k, v in os.environ.items() if k != 'ABUSEIPDB_API_KEY'}
        with patch.dict(os.environ, env, clear=True):
            assert _abuseipdb('1.2.3.4') == -1

    @patch('src.analyzer.requests.get')
    def test_clean_ip_returns_zero(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {'data': {'abuseConfidenceScore': 0}}
        )
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'testkey'}):
            assert _abuseipdb('8.8.8.8') == 0

    @patch('src.analyzer.requests.get')
    def test_malicious_ip_returns_high_score(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {'data': {'abuseConfidenceScore': 95}}
        )
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'testkey'}):
            assert _abuseipdb('1.2.3.4') == 95

    @patch('src.analyzer.requests.get')
    def test_http_error_returns_minus_one(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401, json=lambda: {})
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'badkey'}):
            assert _abuseipdb('1.2.3.4') == -1

    @patch('src.analyzer.requests.get')
    def test_network_error_returns_minus_one(self, mock_get):
        mock_get.side_effect = Exception('Timeout')
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'testkey'}):
            assert _abuseipdb('1.2.3.4') == -1

    @patch('src.analyzer.requests.get')
    def test_key_sent_in_header(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {'data': {'abuseConfidenceScore': 0}}
        )
        with patch.dict(os.environ, {'ABUSEIPDB_API_KEY': 'my-secret-key'}):
            _abuseipdb('1.2.3.4')
        headers = mock_get.call_args[1]['headers']
        assert headers['Key'] == 'my-secret-key'

    def test_threshold_constants_sane(self):
        assert _ABUSEIPDB_SUSPICIOUS < _ABUSEIPDB_MALICIOUS
        assert 0 < _ABUSEIPDB_SUSPICIOUS < 100
        assert 0 < _ABUSEIPDB_MALICIOUS <= 100


# ── _detect_mime ──────────────────────────────────────────────────────────────

class TestDetectMime:
    def test_exe_mz_header(self):
        assert _detect_mime(b'\x4d\x5a' + b'\x00' * 10) == 'application/x-msdownload'

    def test_elf_binary(self):
        assert _detect_mime(b'\x7fELF' + b'\x00' * 10) == 'application/x-elf'

    def test_pdf(self):
        assert _detect_mime(b'%PDF-1.4 rest of file') == 'application/pdf'

    def test_zip(self):
        assert _detect_mime(b'PK\x03\x04' + b'\x00' * 10) == 'application/zip'

    def test_rar(self):
        assert _detect_mime(b'Rar!' + b'\x00' * 10) == 'application/x-rar-compressed'

    def test_gzip(self):
        assert _detect_mime(b'\x1f\x8b' + b'\x00' * 10) == 'application/gzip'

    def test_unknown_returns_none(self):
        assert _detect_mime(b'RandomUnknownData') is None

    def test_empty_returns_none(self):
        assert _detect_mime(b'') is None


# ── _PRIVATE_IP ───────────────────────────────────────────────────────────────

class TestPrivateIp:
    @pytest.mark.parametrize("ip", [
        '10.0.0.1', '10.255.255.255',
        '192.168.0.1', '192.168.255.255',
        '172.16.0.1', '172.31.255.255',
        '127.0.0.1', '127.0.0.255',
        '169.254.1.1',
    ])
    def test_private_ips(self, ip):
        assert _PRIVATE_IP.match(ip), f"{ip} should be private"

    @pytest.mark.parametrize("ip", [
        '8.8.8.8', '1.1.1.1', '203.0.113.10',
        '172.15.0.1', '172.32.0.1', '11.0.0.1',
    ])
    def test_public_ips(self, ip):
        assert not _PRIVATE_IP.match(ip), f"{ip} should be public"


# ── DANGEROUS_EXTENSIONS ──────────────────────────────────────────────────────

class TestDangerousExtensions:
    @pytest.mark.parametrize("ext", [
        '.exe', '.bat', '.cmd', '.ps1', '.vbs',
        '.js', '.hta', '.msi', '.scr', '.dll',
        '.docm', '.xlsm', '.pptm', '.iso', '.lnk',
    ])
    def test_dangerous(self, ext):
        assert ext in DANGEROUS_EXTENSIONS

    @pytest.mark.parametrize("ext", [
        '.pdf', '.docx', '.xlsx', '.txt', '.png',
        '.jpg', '.mp4', '.zip', '.csv',
    ])
    def test_safe(self, ext):
        assert ext not in DANGEROUS_EXTENSIONS


# ── check_headers ─────────────────────────────────────────────────────────────

class TestCheckHeaders:
    def _make(self, **kwargs):
        base = {
            'from': 'Boss <ceo@company.se>',
            'reply_to': '',
            'return_path': '<ceo@company.se>',
            'message_id': '<id@company.se>',
            'received': ['from mx.a.com ([1.2.3.4]) by mx.b.com'],
            'x_mailer': '',
        }
        base.update(kwargs)
        return base

    def test_clean_email_no_flags(self):
        result = check_headers(self._make())
        assert result['flags'] == []
        assert result['reply_mismatch'] == False
        assert result['return_path_mismatch'] == False
        assert result['mid_mismatch'] == False
        assert result['no_received'] == False

    def test_reply_to_mismatch(self):
        result = check_headers(self._make(reply_to='attacker@evil.com'))
        assert result['reply_mismatch'] == True
        assert any('Reply-To' in f for f in result['flags'])

    def test_reply_to_same_domain_no_flag(self):
        result = check_headers(self._make(reply_to='other@company.se'))
        assert result['reply_mismatch'] == False

    def test_return_path_mismatch(self):
        result = check_headers(self._make(return_path='<bounce@evil.com>'))
        assert result['return_path_mismatch'] == True
        assert any('Return-Path' in f for f in result['flags'])

    def test_message_id_mismatch(self):
        result = check_headers(self._make(message_id='<id@other-domain.net>'))
        assert result['mid_mismatch'] == True
        assert any('Message-ID' in f for f in result['flags'])

    def test_no_received_headers(self):
        result = check_headers(self._make(received=[]))
        assert result['no_received'] == True
        assert any('Received' in f for f in result['flags'])

    def test_received_hops_counted(self):
        result = check_headers(self._make(received=['hop1', 'hop2', 'hop3']))
        assert result['received_hops'] == 3

    def test_sender_ip_extracted(self):
        result = check_headers(self._make(
            received=['from mx.evil.com (mx.evil.com [9.9.9.9]) by mx.b.com']
        ))
        assert result['sender_ip'] == '9.9.9.9'

    def test_suspicious_xmailer(self):
        result = check_headers(self._make(x_mailer='Dark Mailer Pro v2'))
        assert any('X-Mailer' in f for f in result['flags'])

    def test_multiple_flags_accumulate(self):
        result = check_headers(self._make(
            reply_to='x@evil.com',
            return_path='<y@evil.com>',
            received=[],
        ))
        assert len(result['flags']) >= 3

    def test_from_domain_extracted(self):
        result = check_headers(self._make())
        assert result['from_domain'] == 'company.se'

    def test_phishing_email(self):
        msg = message_from_bytes(PHISHING_EML)
        parsed = parse_email(msg)
        result = check_headers(parsed['headers'])
        assert result['reply_mismatch'] == True
        assert result['return_path_mismatch'] == True
        assert result['mid_mismatch'] == True


# ── check_authentication ──────────────────────────────────────────────────────

def _make_txt_answer(text: str):
    answer = MagicMock()
    answer.strings = [text.encode()]
    return [answer]


class TestCheckAuthentication:
    def test_empty_domain_returns_early(self):
        result = check_authentication('')
        assert result['domain'] == ''
        assert result['spf']['result'] == 'missing'
        assert result['dmarc']['result'] == 'missing'
        assert result['dkim']['result'] == 'missing'
        assert len(result['flags']) > 0

    @patch('src.analyzer.dns.resolver.resolve')
    def test_spf_found(self, mock_resolve):
        def side_effect(domain, rtype, **kwargs):
            if rtype == 'TXT' and not domain.startswith('_'):
                return _make_txt_answer('v=spf1 mx ~all')
            raise dns.resolver.NXDOMAIN()
        mock_resolve.side_effect = side_effect

        result = check_authentication('example.com')
        assert result['spf']['result'] == 'found'
        assert result['spf']['record'] == 'v=spf1 mx ~all'

    @patch('src.analyzer.dns.resolver.resolve')
    def test_spf_missing(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = check_authentication('example.com')
        assert result['spf']['result'] == 'missing'
        assert any('SPF' in f for f in result['flags'])

    @patch('src.analyzer.dns.resolver.resolve')
    def test_dmarc_found_policy_parsed(self, mock_resolve):
        def side_effect(domain, rtype, **kwargs):
            if '_dmarc' in domain:
                return _make_txt_answer('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')
            raise dns.resolver.NXDOMAIN()
        mock_resolve.side_effect = side_effect

        result = check_authentication('example.com')
        assert result['dmarc']['result'] == 'found'
        assert result['dmarc']['policy'] == 'reject'

    @patch('src.analyzer.dns.resolver.resolve')
    def test_dmarc_policy_none_flagged(self, mock_resolve):
        def side_effect(domain, rtype, **kwargs):
            if '_dmarc' in domain:
                return _make_txt_answer('v=DMARC1; p=none')
            raise dns.resolver.NXDOMAIN()
        mock_resolve.side_effect = side_effect

        result = check_authentication('example.com')
        assert result['dmarc']['policy'] == 'none'
        assert any('none' in f for f in result['flags'])

    @patch('src.analyzer.dns.resolver.resolve')
    def test_dkim_dns_record_found(self, mock_resolve):
        def side_effect(domain, rtype, **kwargs):
            if '_domainkey' in domain:
                return _make_txt_answer('v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQ')
            raise dns.resolver.NXDOMAIN()
        mock_resolve.side_effect = side_effect

        result = check_authentication('example.com')
        assert result['dkim']['result'] == 'found'
        assert result['dkim']['selector'] != ''

    @patch('src.analyzer.dns.resolver.resolve')
    def test_dkim_dns_missing_flagged(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = check_authentication('example.com')
        assert result['dkim']['result'] == 'missing'
        assert any('DKIM' in f for f in result['flags'])

    @patch('src.analyzer._verify_dkim', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_dkim_signature_invalid_flagged(self, mock_resolve, mock_dkim):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        raw = b'DKIM-Signature: v=1; ...\r\nFrom: x@y.com\r\n\r\nbody'
        result = check_authentication('y.com', raw_bytes=raw)
        assert result['dkim']['signature_present'] == True
        assert result['dkim']['signature_valid'] == False
        assert any('verification failed' in f for f in result['flags'])

    @patch('src.analyzer._verify_dkim', return_value=True)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_dkim_signature_valid_no_flag(self, mock_resolve, mock_dkim):
        def side_effect(domain, rtype, **kwargs):
            if '_domainkey' in domain:
                return _make_txt_answer('v=DKIM1; p=MIGf')
            raise dns.resolver.NXDOMAIN()
        mock_resolve.side_effect = side_effect

        raw = b'DKIM-Signature: v=1; ...\r\nFrom: x@y.com\r\n\r\nbody'
        result = check_authentication('y.com', raw_bytes=raw)
        assert result['dkim']['signature_valid'] == True
        assert not any('verification failed' in f for f in result['flags'])

    @patch('src.analyzer.dns.resolver.resolve')
    def test_dns_timeout_handled_gracefully(self, mock_resolve):
        mock_resolve.side_effect = Exception('Timeout')
        result = check_authentication('example.com')
        assert result['spf']['result'] == 'missing'
        assert result['dmarc']['result'] == 'missing'


# ── check_reputation ──────────────────────────────────────────────────────────

class TestCheckReputation:
    def test_empty_ip_skipped(self):
        result = check_reputation('')
        assert result['spamhaus_zen'] == False
        assert result['threatfox_ip'] == False
        assert result['abuseipdb_score'] == -1
        assert result['flags'] == []

    @pytest.mark.parametrize("ip", ['192.168.1.1', '10.0.0.1', '127.0.0.1'])
    def test_private_ip_skipped(self, ip):
        result = check_reputation(ip)
        assert result['spamhaus_zen'] == False
        assert result['threatfox_ip'] == False
        assert result['abuseipdb_score'] == -1
        assert result['flags'] == []

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_listed_on_zen(self, mock_resolve, mock_tf, mock_ab):
        mock_resolve.return_value = MagicMock()
        result = check_reputation('1.2.3.4')
        assert result['spamhaus_zen'] == True
        assert any('Spamhaus' in f for f in result['flags'])

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_clean_ip(self, mock_resolve, mock_tf, mock_ab):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = check_reputation('8.8.8.8')
        assert result['spamhaus_zen'] == False
        assert result['flags'] == []

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_dns_error_treated_as_clean(self, mock_resolve, mock_tf, mock_ab):
        mock_resolve.side_effect = Exception('Network error')
        result = check_reputation('5.5.5.5')
        assert result['spamhaus_zen'] == False

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_ip_reversed_for_lookup(self, mock_resolve, mock_tf, mock_ab):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        check_reputation('1.2.3.4')
        call_args = mock_resolve.call_args[0][0]
        assert call_args.startswith('4.3.2.1.')

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    def test_threatfox_hit_flagged(self, mock_dns, mock_ab):
        with patch('src.analyzer._threatfox', return_value=True):
            result = check_reputation('1.2.3.4')
        assert result['threatfox_ip'] == True
        assert any('ThreatFox' in f for f in result['flags'])

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    def test_abuseipdb_malicious_flagged(self, mock_dns, mock_tf):
        with patch('src.analyzer._abuseipdb', return_value=95):
            result = check_reputation('1.2.3.4')
        assert result['abuseipdb_score'] == 95
        assert any('AbuseIPDB' in f for f in result['flags'])

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    def test_abuseipdb_suspicious_flagged(self, mock_dns, mock_tf):
        with patch('src.analyzer._abuseipdb', return_value=50):
            result = check_reputation('1.2.3.4')
        assert result['abuseipdb_score'] == 50
        assert any('elevated' in f for f in result['flags'])

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN())
    def test_abuseipdb_not_configured_no_flag(self, mock_dns, mock_tf):
        with patch('src.analyzer._abuseipdb', return_value=-1):
            result = check_reputation('1.2.3.4')
        assert result['abuseipdb_score'] == -1
        assert not any('AbuseIPDB' in f for f in result['flags'])


# ── check_urls ────────────────────────────────────────────────────────────────

class TestCheckUrls:
    def test_empty_list(self):
        result = check_urls([])
        assert result['urlhaus_hits'] == 0
        assert result['dbl_hits'] == 0
        assert result['flags'] == []

    @patch('src.analyzer._urlhaus', return_value=True)
    @patch('src.analyzer._dnsbl', return_value=False)
    def test_urlhaus_hit(self, mock_dbl, mock_uh):
        result = check_urls(['http://malware.com/payload'])
        assert result['urlhaus_hits'] == 1
        assert any('URLhaus' in f for f in result['flags'])

    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=True)
    def test_dbl_hit(self, mock_dbl, mock_uh):
        result = check_urls(['http://spammy-domain.com/page'])
        assert result['dbl_hits'] == 1
        assert any('DBL' in f for f in result['flags'])

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    def test_clean_urls(self, mock_dbl, mock_uh, mock_tf):
        result = check_urls(['https://google.com', 'https://github.com'])
        assert result['urlhaus_hits'] == 0
        assert result['dbl_hits'] == 0
        assert result['threatfox_hits'] == 0
        assert result['flags'] == []

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    def test_capped_at_max(self, mock_dbl, mock_uh, mock_tf):
        urls = [f'https://url{i}.com' for i in range(25)]
        result = check_urls(urls)
        assert result['total'] == 25
        assert result['checked'] == 15

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    def test_duplicates_deduplicated(self, mock_dbl, mock_uh, mock_tf):
        urls = ['https://same.com'] * 5
        result = check_urls(urls)
        assert result['checked'] == 1

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=True)
    @patch('src.analyzer._dnsbl', return_value=False)
    def test_multiple_hits_counted(self, mock_dbl, mock_uh, mock_tf):
        result = check_urls(['http://a.com', 'http://b.com', 'http://c.com'])
        assert result['urlhaus_hits'] == 3

    @patch('src.analyzer._threatfox', return_value=True)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    def test_threatfox_domain_hit(self, mock_dbl, mock_uh, mock_tf):
        result = check_urls(['http://c2-server.com/beacon'])
        assert result['threatfox_hits'] == 1
        assert any('ThreatFox' in f for f in result['flags'])

    def test_empty_list_has_threatfox_hits_key(self):
        result = check_urls([])
        assert 'threatfox_hits' in result
        assert result['threatfox_hits'] == 0


# ── check_attachments ─────────────────────────────────────────────────────────

class TestCheckAttachments:
    def test_empty_list(self):
        result = check_attachments([])
        assert result['count'] == 0
        assert result['malwarebazaar_hits'] == 0
        assert result['flags'] == []

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    def test_dangerous_extension_flagged(self, mock_mb, mock_tf):
        atts = [{'filename': 'virus.exe', 'content_type': 'application/octet-stream',
                 'data': b'\x00' * 20, 'size': 20}]
        result = check_attachments(atts)
        assert result['results'][0]['dangerous'] == True
        assert any('.exe' in f for f in result['flags'])

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    def test_mime_mismatch_flagged(self, mock_mb, mock_tf):
        # Declared as PDF, but magic bytes say EXE
        atts = [{'filename': 'fakepdf.pdf', 'content_type': 'application/pdf',
                 'data': b'\x4d\x5a' + b'\x00' * 20, 'size': 22}]
        result = check_attachments(atts)
        assert result['results'][0]['mime_mismatch'] == True
        assert any('MIME' in f for f in result['flags'])

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=True)
    def test_malwarebazaar_hit_flagged(self, mock_mb, mock_tf):
        atts = [{'filename': 'malware.bin', 'content_type': 'application/octet-stream',
                 'data': b'\x00' * 20, 'size': 20}]
        result = check_attachments(atts)
        assert result['malwarebazaar_hits'] == 1
        assert any('MalwareBazaar' in f for f in result['flags'])

    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._threatfox', return_value=True)
    def test_threatfox_hit_flagged(self, mock_tf, mock_mb):
        atts = [{'filename': 'rat.exe', 'content_type': 'application/octet-stream',
                 'data': b'\x4d\x5a' + b'\x00' * 20, 'size': 22}]
        result = check_attachments(atts)
        assert result['threatfox_hits'] == 1
        assert any('ThreatFox' in f for f in result['flags'])

    def test_empty_list_has_threatfox_hits_key(self):
        result = check_attachments([])
        assert 'threatfox_hits' in result
        assert result['threatfox_hits'] == 0

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    def test_sha256_computed(self, mock_mb, mock_tf):
        data = b'test content'
        atts = [{'filename': 'file.txt', 'content_type': 'text/plain',
                 'data': data, 'size': len(data)}]
        result = check_attachments(atts)
        assert result['results'][0]['sha256'] == _sha256(data)
        assert len(result['results'][0]['sha256']) == 64

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    def test_clean_attachment_no_flags(self, mock_mb, mock_tf):
        # Real PDF magic bytes, declared as PDF
        atts = [{'filename': 'doc.pdf', 'content_type': 'application/pdf',
                 'data': b'%PDF-1.4 rest of content', 'size': 24}]
        result = check_attachments(atts)
        assert result['results'][0]['dangerous'] == False
        assert result['results'][0]['mime_mismatch'] == False
        assert result['malwarebazaar_hits'] == 0
        assert result['flags'] == []

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    def test_double_extension_exe_dangerous(self, mock_mb, mock_tf):
        atts = [{'filename': 'invoice.pdf.exe', 'content_type': 'application/pdf',
                 'data': b'\x4d\x5a' + b'\x00' * 20, 'size': 22}]
        result = check_attachments(atts)
        r = result['results'][0]
        assert r['extension'] == '.exe'
        assert r['dangerous'] == True
        assert r['mime_mismatch'] == True

    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    def test_no_data_no_crash(self, mock_mb, mock_tf):
        atts = [{'filename': 'empty.txt', 'content_type': 'text/plain',
                 'data': b'', 'size': 0}]
        result = check_attachments(atts)
        assert result['results'][0]['sha256'] == ''


# ── _calculate_verdict ────────────────────────────────────────────────────────

class TestCalculateVerdict:
    def _v(self, **overrides):
        hf = make_header_findings(**{k: v for k, v in overrides.items()
                                     if k in make_header_findings()})
        af = make_auth_findings()
        rf = make_rep_findings()
        uf = make_url_findings()
        atf = make_att_findings()

        if 'auth' in overrides:
            af = overrides['auth']
        if 'rep' in overrides:
            rf = overrides['rep']
        if 'urls' in overrides:
            uf = overrides['urls']
        if 'atts' in overrides:
            atf = overrides['atts']

        return _calculate_verdict(hf, af, rf, uf, atf)

    def test_saekert_all_clean(self):
        assert self._v() == 'MOST LIKELY SAFE'

    def test_osaekert_reply_mismatch(self):
        assert self._v(reply_mismatch=True) == 'MOST LIKELY UNSAFE'

    def test_osaekert_return_path_mismatch(self):
        assert self._v(return_path_mismatch=True) == 'MOST LIKELY UNSAFE'

    def test_osaekert_spamhaus(self):
        assert self._v(rep=make_rep_findings(listed=True)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_urlhaus(self):
        assert self._v(urls=make_url_findings(urlhaus=1)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_dbl(self):
        assert self._v(urls=make_url_findings(dbl=1)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_malwarebazaar(self):
        assert self._v(atts=make_att_findings(mb_hits=1)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_dkim_sig_invalid(self):
        auth = make_auth_findings(sig_present=True, sig_valid=False)
        assert self._v(auth=auth) == 'MOST LIKELY UNSAFE'

    def test_osaekert_two_auth_missing(self):
        auth = make_auth_findings(spf='missing', dmarc='missing')
        assert self._v(auth=auth) == 'MOST LIKELY UNSAFE'

    def test_osaekert_all_three_auth_missing(self):
        auth = make_auth_findings(spf='missing', dmarc='missing', dkim='missing')
        assert self._v(auth=auth) == 'MOST LIKELY UNSAFE'

    def test_ytterligare_one_auth_missing(self):
        auth = make_auth_findings(spf='missing')
        assert self._v(auth=auth) == 'FURTHER ANALYSIS REQUIRED'

    def test_ytterligare_dmarc_policy_none(self):
        auth = make_auth_findings(policy='none')
        assert self._v(auth=auth) == 'FURTHER ANALYSIS REQUIRED'

    def test_ytterligare_mid_mismatch(self):
        assert self._v(mid_mismatch=True) == 'FURTHER ANALYSIS REQUIRED'

    def test_ytterligare_no_received(self):
        assert self._v(no_received=True) == 'FURTHER ANALYSIS REQUIRED'

    def test_ytterligare_dangerous_ext(self):
        atts = make_att_findings(results=[{'dangerous': True, 'mime_mismatch': False}])
        assert self._v(atts=atts) == 'FURTHER ANALYSIS REQUIRED'

    def test_ytterligare_mime_mismatch(self):
        atts = make_att_findings(results=[{'dangerous': False, 'mime_mismatch': True}])
        assert self._v(atts=atts) == 'FURTHER ANALYSIS REQUIRED'

    def test_dkim_sig_valid_does_not_flag(self):
        auth = make_auth_findings(sig_present=True, sig_valid=True)
        assert self._v(auth=auth) == 'MOST LIKELY SAFE'

    def test_dkim_sig_unverified_does_not_osäkert(self):
        auth = make_auth_findings(sig_present=True, sig_valid=None)
        assert self._v(auth=auth) != 'MOST LIKELY UNSAFE'

    def test_saekert_requires_reject_or_quarantine(self):
        auth_quarantine = make_auth_findings(policy='quarantine')
        assert self._v(auth=auth_quarantine) == 'MOST LIKELY SAFE'

    def test_ytterligare_with_dmarc_policy_none_despite_all_found(self):
        auth = make_auth_findings(spf='found', dmarc='found', dkim='found', policy='none')
        assert self._v(auth=auth) == 'FURTHER ANALYSIS REQUIRED'

    def test_osaekert_threatfox_ip(self):
        assert self._v(rep=make_rep_findings(threatfox=True)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_threatfox_url(self):
        assert self._v(urls=make_url_findings(threatfox=1)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_threatfox_attachment(self):
        assert self._v(atts=make_att_findings(tf_hits=1)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_abuseipdb_malicious(self):
        assert self._v(rep=make_rep_findings(abuseipdb=_ABUSEIPDB_MALICIOUS)) == 'MOST LIKELY UNSAFE'

    def test_osaekert_abuseipdb_hundred(self):
        assert self._v(rep=make_rep_findings(abuseipdb=100)) == 'MOST LIKELY UNSAFE'

    def test_ytterligare_abuseipdb_suspicious(self):
        assert self._v(rep=make_rep_findings(abuseipdb=_ABUSEIPDB_SUSPICIOUS)) == 'FURTHER ANALYSIS REQUIRED'

    def test_ytterligare_abuseipdb_mid_range(self):
        assert self._v(rep=make_rep_findings(abuseipdb=50)) == 'FURTHER ANALYSIS REQUIRED'

    def test_saekert_abuseipdb_not_configured(self):
        # score=-1 means not configured – should not affect verdict
        assert self._v(rep=make_rep_findings(abuseipdb=-1)) == 'MOST LIKELY SAFE'

    def test_saekert_abuseipdb_zero(self):
        # score=0 means clean
        assert self._v(rep=make_rep_findings(abuseipdb=0)) == 'MOST LIKELY SAFE'

    def test_saekert_abuseipdb_low(self):
        # score below suspicious threshold is not a flag
        assert self._v(rep=make_rep_findings(abuseipdb=_ABUSEIPDB_SUSPICIOUS - 1)) == 'MOST LIKELY SAFE'


# ── analyze() – full pipeline with all network mocked ────────────────────────

class TestAnalyzeFull:
    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_clean_email_saekert(self, mock_dns, mock_dbl, mock_uh, mock_mb, mock_tf, mock_ab):
        def dns_side(domain, rtype, **kwargs):
            if rtype == 'TXT':
                if domain.startswith('_dmarc'):
                    return _make_txt_answer('v=DMARC1; p=reject')
                elif '_domainkey' in domain:
                    return _make_txt_answer('v=DKIM1; p=MIGf')
                else:
                    return _make_txt_answer('v=spf1 mx ~all')
            raise dns.resolver.NXDOMAIN()
        mock_dns.side_effect = dns_side

        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        result = analyze(parsed, raw_bytes=CLEAN_EML)

        assert result['verdict'] == 'MOST LIKELY SAFE'
        assert result['domain'] == 'legit.se'
        assert 'header_findings' in result
        assert 'auth_findings' in result
        assert 'rep_findings' in result
        assert 'url_findings' in result
        assert 'att_findings' in result
        assert 'all_flags' in result

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_phishing_email_osaekert(self, mock_dns, mock_dbl, mock_uh, mock_mb, mock_tf, mock_ab):
        mock_dns.side_effect = dns.resolver.NXDOMAIN()

        msg = message_from_bytes(PHISHING_EML)
        parsed = parse_email(msg)
        result = analyze(parsed, raw_bytes=PHISHING_EML)

        assert result['verdict'] == 'MOST LIKELY UNSAFE'
        assert len(result['all_flags']) > 0

    @patch('src.analyzer._malwarebazaar', return_value=True)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_malware_attachment_osaekert(self, mock_dns, mock_dbl, mock_uh, mock_mb):
        mock_dns.side_effect = dns.resolver.NXDOMAIN()

        msg = message_from_bytes(ATTACHMENT_EML)
        parsed = parse_email(msg)
        result = analyze(parsed, raw_bytes=ATTACHMENT_EML)

        assert result['verdict'] == 'MOST LIKELY UNSAFE'
        assert result['att_findings']['malwarebazaar_hits'] >= 1

    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=True)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_malicious_url_osaekert(self, mock_dns, mock_dbl, mock_uh, mock_mb):
        mock_dns.side_effect = dns.resolver.NXDOMAIN()

        msg = message_from_bytes(MALWARE_EML)
        parsed = parse_email(msg)
        result = analyze(parsed, raw_bytes=MALWARE_EML)

        assert result['verdict'] == 'MOST LIKELY UNSAFE'
        assert result['url_findings']['urlhaus_hits'] >= 1

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_result_is_stateless(self, mock_dns, mock_dbl, mock_uh, mock_mb, mock_tf, mock_ab):
        mock_dns.side_effect = dns.resolver.NXDOMAIN()

        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        r1 = analyze(parsed, raw_bytes=CLEAN_EML)
        r2 = analyze(parsed, raw_bytes=CLEAN_EML)

        assert r1['verdict'] == r2['verdict']
        assert r1['all_flags'] == r2['all_flags']

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_no_raw_bytes_still_works(self, mock_dns, mock_dbl, mock_uh, mock_mb, mock_tf, mock_ab):
        mock_dns.side_effect = dns.resolver.NXDOMAIN()

        msg = message_from_bytes(CLEAN_EML)
        parsed = parse_email(msg)
        result = analyze(parsed)  # no raw_bytes

        assert 'verdict' in result
        assert result['auth_findings']['dkim']['signature_present'] == False

    @patch('src.analyzer._abuseipdb', return_value=-1)
    @patch('src.analyzer._threatfox', return_value=False)
    @patch('src.analyzer._malwarebazaar', return_value=False)
    @patch('src.analyzer._urlhaus', return_value=False)
    @patch('src.analyzer._dnsbl', return_value=False)
    @patch('src.analyzer.dns.resolver.resolve')
    def test_all_flags_aggregated(self, mock_dns, mock_dbl, mock_uh, mock_mb, mock_tf, mock_ab):
        mock_dns.side_effect = dns.resolver.NXDOMAIN()

        msg = message_from_bytes(PHISHING_EML)
        parsed = parse_email(msg)
        result = analyze(parsed, raw_bytes=PHISHING_EML)

        total_flags = (
            len(result['header_findings']['flags']) +
            len(result['auth_findings']['flags']) +
            len(result['rep_findings']['flags']) +
            len(result['url_findings']['flags']) +
            len(result['att_findings']['flags'])
        )
        assert len(result['all_flags']) == total_flags


def _make_txt_answer(text: str):
    answer = MagicMock()
    answer.strings = [text.encode()]
    return [answer]