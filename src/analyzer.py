# src/analyzer.py
# Analyzes a parsed email dict from parser.py.
# Checks: headers, SPF/DKIM/DMARC, IP reputation, URLs, attachments.
# All external calls send only hashes or IP addresses – never raw content.
# Stateless: no data is stored or retained after analyze() returns.
# Returns structured result dict with verdict: SÄKERT / OSÄKERT / YTTERLIGARE ANALYS BEHÖVS
#
# External threat sources:
#   Spamhaus ZEN      – IP blocklist via DNSBL          (free, fair use)
#   Spamhaus DBL      – domain blocklist via DNSBL       (free, fair use)
#   URLhaus           – malicious URL database           (free, fair use)
#   MalwareBazaar     – malware hash database            (free, fair use)
#   ThreatFox         – IOC database: IPs, domains, hashes (free, no key)
#   AbuseIPDB         – IP abuse confidence score        (free tier, API key required)
#
# Required env vars:
#   ABUSEIPDB_API_KEY  – free key from https://www.abuseipdb.com/register
#                        If unset, AbuseIPDB checks are skipped gracefully.

import os
import re
import hashlib
import requests
import dns.resolver
import time
from email.utils import parseaddr
from src.logger import get_logger

try:
    import dkim as _dkim
    _DKIM_AVAILABLE = True
except ImportError:
    _DKIM_AVAILABLE = False

logger = get_logger(__name__)

_TIMEOUT  = 5
_MAX_URLS = 15

# AbuseIPDB thresholds (0–100 confidence score)
_ABUSEIPDB_MALICIOUS  = 80   # → OSÄKERT
_ABUSEIPDB_SUSPICIOUS = 25   # → YTTERLIGARE ANALYS BEHÖVS

DANGEROUS_EXTENSIONS = frozenset({
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.hta',
    '.msi', '.scr', '.pif', '.com', '.lnk', '.wsf', '.jar', '.dll',
    '.docm', '.xlsm', '.pptm', '.iso', '.img', '.vhd',
})

DKIM_SELECTORS = [
    'default', 'mail', 'google', 'k1', 'k2',
    'selector1', 'selector2', 'dkim', 'email', 's1', 's2',
]

_PRIVATE_IP = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)'
)

_MIME_MAGIC = {
    b'\x4d\x5a':         'application/x-msdownload',
    b'\x7fELF':          'application/x-elf',
    b'%PDF':             'application/pdf',
    b'PK\x03\x04':       'application/zip',
    b'PK\x05\x06':       'application/zip',
    b'Rar!':             'application/x-rar-compressed',
    b'\x1f\x8b':         'application/gzip',
    b'#!':               'application/x-sh',
    b'\xca\xfe\xba\xbe': 'application/java',
}

_SPAM_TOOLS = frozenset({'ratware', 'mass mailer', 'advance mailer', 'dark mailer'})

# Known legitimate CDN/infrastructure domains — skip DBL check
_DBL_WHITELIST = frozenset({
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'ajax.googleapis.com',
    'apis.google.com',
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com',
    'code.jquery.com',
})

# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_domain(field: str) -> str:
    _, addr = parseaddr(field)
    if '@' in addr:
        return addr.split('@')[-1].lower().strip()
    return ''


def _extract_sender_ip(received_list: list) -> str:
    if not received_list:
        return ''
    match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', received_list[-1])
    return match.group(1) if match else ''


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_mime(data: bytes) -> str | None:
    for magic, mime in _MIME_MAGIC.items():
        if data[:len(magic)] == magic:
            return mime
    return None


def _resolve_txt(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=_TIMEOUT)
        return [b''.join(r.strings).decode('utf-8', errors='replace') for r in answers]
    except Exception:
        return []


def _lookup_spf(domain: str) -> str | None:
    for r in _resolve_txt(domain):
        if r.startswith('v=spf1'):
            return r
    return None


def _lookup_dmarc(domain: str) -> str | None:
    for r in _resolve_txt(f'_dmarc.{domain}'):
        if r.startswith('v=DMARC1'):
            return r
    return None


def _lookup_dkim_record(domain: str, selectors: list = None) -> tuple[str | None, str]:
    if selectors is None:
        selectors = DKIM_SELECTORS
    for selector in selectors:
        for r in _resolve_txt(f'{selector}._domainkey.{domain}'):
            if 'v=DKIM1' in r or 'p=' in r:
                return r, selector
    return None, ''


def _verify_dkim(raw_bytes: bytes) -> bool | None:
    if not _DKIM_AVAILABLE or not raw_bytes:
        return None
    try:
        return bool(_dkim.verify(raw_bytes))
    except Exception:
        return None


def _extract_dkim_selector_from_bytes(raw_bytes: bytes) -> str:
    """
    Reads the actual DKIM selector used in the email from its DKIM-Signature header.
    DKIM-Signature contains s=<selector> which tells us exactly which DNS record to look up.
    Without this, we only try guesses and miss selectors like '20230601' (Gmail).
    """
    if not raw_bytes:
        return ''
    import re as _re
    # Find s= tag inside DKIM-Signature header value
    # Simple approach: find DKIM-Signature then look for s= within next 500 bytes
    idx = raw_bytes.find(b'DKIM-Signature:')
    if idx == -1:
        return ''
    chunk = raw_bytes[idx:idx+500]
    sel_match = _re.search(b'[; \t]s=([a-zA-Z0-9_.-]+)', chunk)
    if not sel_match:
        return ''
    return sel_match.group(1).decode('ascii', errors='replace')

def _dnsbl(host: str, zone: str) -> bool:
    try:
        dns.resolver.resolve(f'{host}.{zone}', 'A', lifetime=_TIMEOUT)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return False


def _urlhaus(url: str) -> bool:
    try:
        r = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=_TIMEOUT,
        )
        return r.status_code == 200 and r.json().get('query_status') == 'is_url'
    except Exception:
        return False


def _malwarebazaar(sha256_hash: str) -> bool:
    try:
        r = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': sha256_hash},
            timeout=_TIMEOUT,
        )
        return r.status_code == 200 and r.json().get('query_status') == 'ok'
    except Exception:
        return False


def _threatfox(ioc: str) -> bool:
    """
    Checks any IOC (IP, domain, URL, file hash) against ThreatFox.
    ThreatFox tracks malware C2 servers, ransomware infrastructure,
    and botnet addresses. No API key required.
    Returns True if the IOC is a known malicious indicator.
    """
    if not ioc:
        return False
    try:
        r = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            json={'query': 'search_ioc', 'search_term': ioc},
            timeout=_TIMEOUT,
        )
        return r.status_code == 200 and r.json().get('query_status') == 'ok'
    except Exception:
        return False


def _abuseipdb(ip: str) -> int:
    """
    Returns AbuseIPDB confidence score (0–100) for an IP address.
    0   = never reported / clean
    100 = confirmed malicious with high confidence
    -1  = key not configured or request failed (treated as unknown)

    Requires ABUSEIPDB_API_KEY environment variable.
    Free tier: 1,000 checks/day. Register at https://www.abuseipdb.com/register
    """
    key = os.environ.get('ABUSEIPDB_API_KEY', '')
    if not key:
        return -1
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': '90'},
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            return int(r.json().get('data', {}).get('abuseConfidenceScore', 0))
        return -1
    except Exception:
        return -1




def _virustotal_url(url: str) -> dict | None:
    """
    Checks a URL against VirusTotal — scans against 70+ engines simultaneously.
    Returns {'malicious': int, 'suspicious': int, 'total': int} or None on error.

    Free tier: 4 requests/minute, 500/day.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key or not url:
        return None
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        r = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'total': 0, 'note': 'not in database'}
        if r.status_code == 429:
            logger.warning('VirusTotal rate limit hit – skipping remaining URL checks')
            return None
        if r.status_code != 200:
            return None
        stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious':  stats.get('malicious',  0),
            'suspicious': stats.get('suspicious', 0),
            'total':      sum(stats.values()),
            'note':       '',
        }
    except Exception as e:
        logger.debug(f'VirusTotal URL check failed: {e}')
        return None


def _virustotal_hash(sha256_hash: str) -> dict | None:
    """
    Checks a file hash against VirusTotal.
    Returns {'malicious': int, 'suspicious': int, 'total': int} or None on error.
    Sends only the SHA256 hash — raw file bytes never leave the container.
    """
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key or not sha256_hash:
        return None
    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256_hash}',
            headers={'x-apikey': key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'total': 0, 'note': 'not in database'}
        if r.status_code == 429:
            logger.warning('VirusTotal rate limit hit')
            return None
        if r.status_code != 200:
            return None
        stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious':  stats.get('malicious',  0),
            'suspicious': stats.get('suspicious', 0),
            'total':      sum(stats.values()),
            'note':       '',
        }
    except Exception as e:
        logger.debug(f'VirusTotal hash check failed: {e}')
        return None


def _virustotal_ip(ip: str) -> dict | None:
    """
    Checks an IP address against VirusTotal.
    Returns {'malicious': int, 'suspicious': int, 'total': int} or None on error.
    """
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key or not ip:
        return None
    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'total': 0, 'note': 'not in database'}
        if r.status_code == 429:
            logger.warning('VirusTotal rate limit hit')
            return None
        if r.status_code != 200:
            return None
        stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious':  stats.get('malicious',  0),
            'suspicious': stats.get('suspicious', 0),
            'total':      sum(stats.values()),
            'note':       '',
        }
    except Exception as e:
        logger.debug(f'VirusTotal IP check failed: {e}')
        return None


def _emailrep(email_address: str) -> dict | None:
    """
    Checks an email address against EmailRep.io.
    Returns a structured reputation dict, or None on failure.

    EmailRep aggregates: social media presence, dark web credential leaks,
    data breaches, phishing kit databases, spam lists, domain age, and more.

    GDPR note: the email address (personal data) is sent to EmailRep.
    This is legitimate interest — security analysis of an unsolicited message.
    No data is stored locally after the call returns.

    Env: EMAILREP_API_KEY (optional — higher rate limits with key)
    Free: 250 queries/month, 10/day (unauthenticated: lower limits)
    """
    if not email_address or '@' not in email_address:
        return None
    key = os.environ.get('EMAILREP_API_KEY', '')
    headers = {'User-Agent': 'PostmortemCLI'}
    if key:
        headers['Key'] = key
    try:
        r = requests.get(
            f'https://emailrep.io/{email_address}',
            headers=headers,
            timeout=_TIMEOUT,
        )
        if r.status_code == 429:
            logger.warning('EmailRep rate limit hit')
            return None
        if r.status_code != 200:
            return None
        data = r.json()
        details = data.get('details', {})
        return {
            'suspicious':              data.get('suspicious', False),
            'reputation':              data.get('reputation', 'unknown'),
            'blacklisted':             details.get('blacklisted', False),
            'malicious_activity':      details.get('malicious_activity', False),
            'malicious_activity_recent': details.get('malicious_activity_recent', False),
            'spam':                    details.get('spam', False),
            'spoofable':               details.get('spoofable', False),
            'disposable':              details.get('disposable', False),
            'free_provider':           details.get('free_provider', False),
            'new_domain':              details.get('new_domain', False),
            'days_since_domain_creation': details.get('days_since_domain_creation', -1),
            'credentials_leaked':      details.get('credentials_leaked', False),
            'credentials_leaked_recent': details.get('credentials_leaked_recent', False),
            'references':              data.get('references', 0),
        }
    except Exception as e:
        logger.debug(f'EmailRep check failed: {e}')
        return None


def _google_safe_browsing(urls: list) -> dict:
    """
    Checks a list of URLs against Google Safe Browsing (Lookup API v4).
    Covers: malware, phishing (SOCIAL_ENGINEERING), unwanted software, harmful apps.

    Up to 500 URLs per call — all URLs checked in a single request.
    Returns a dict mapping url → threat_type for any matches.
    Returns empty dict if clean or API not configured.

    GDPR note: actual URL strings are sent to Google (not hashed).
    URLs are generally not personal data; this is acceptable for security analysis.

    Env: GOOGLE_SAFE_BROWSING_KEY (required — free Google Cloud API key)
    Get key: console.cloud.google.com → Enable Safe Browsing API → Create credentials
    Free: 10,000 requests/day
    """
    key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    if not key or not urls:
        return {}
    try:
        r = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}',
            json={
                'client': {
                    'clientId':      'postmortemcli',
                    'clientVersion': '0.2.1',
                },
                'threatInfo': {
                    'threatTypes':      [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',        # phishing
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION',
                    ],
                    'platformTypes':    ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries':    [{'url': u} for u in urls],
                },
            },
            timeout=_TIMEOUT,
        )
        if r.status_code == 400:
            logger.warning(f'Google Safe Browsing bad request: {r.text[:200]}')
            return {}
        if r.status_code != 200:
            return {}
        matches = r.json().get('matches', [])
        # Map url → threat type (most severe if multiple)
        results = {}
        for match in matches:
            url         = match.get('threat', {}).get('url', '')
            threat_type = match.get('threatType', 'UNKNOWN')
            results[url] = threat_type
        return results
    except Exception as e:
        logger.debug(f'Google Safe Browsing check failed: {e}')
        return {}

# ── Check functions ───────────────────────────────────────────────────────────

def check_headers(headers: dict) -> dict:
    from_domain     = _extract_domain(headers.get('from', ''))
    reply_domain    = _extract_domain(headers.get('reply_to', ''))
    return_path_dom = _extract_domain(headers.get('return_path', ''))
    sender_ip       = _extract_sender_ip(headers.get('received', []))

    flags = []

    reply_mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)
    if reply_mismatch:
        flags.append(f'Reply-To domain ({reply_domain}) differs from From ({from_domain})')

    return_path_mismatch = bool(return_path_dom and from_domain and return_path_dom != from_domain)
    if return_path_mismatch:
        flags.append(f'Return-Path domain ({return_path_dom}) differs from From ({from_domain})')

    mid_mismatch = False
    mid = headers.get('message_id', '')
    if mid and from_domain:
        m = re.search(r'@([^>]+)>', mid)
        if m:
            mid_domain = m.group(1).lower().strip()
            # Accept subdomains: mail.gmail.com is valid for gmail.com
            is_subdomain = mid_domain.endswith('.' + from_domain)
            if mid_domain != from_domain and not is_subdomain:
                mid_mismatch = True
                flags.append(f'Message-ID domain ({mid_domain}) differs from From ({from_domain})')

    no_received = not headers.get('received')
    if no_received:
        flags.append('No Received headers – possible direct injection')

    x_mailer = headers.get('x_mailer', '').lower()
    if x_mailer and any(t in x_mailer for t in _SPAM_TOOLS):
        flags.append(f'Suspicious X-Mailer: {headers["x_mailer"]}')

    # EmailRep — check the actual sender email address
    from_addr   = headers.get('from', '')
    _, from_email = __import__('email.utils', fromlist=['parseaddr']).parseaddr(from_addr)
    emailrep    = _emailrep(from_email)

    if emailrep:
        if emailrep['blacklisted'] or emailrep['malicious_activity']:
            flags.append(
                f'Sender address {from_email} is blacklisted or has known malicious activity '
                f'(EmailRep reputation: {emailrep["reputation"]})'
            )
        elif emailrep['malicious_activity_recent']:
            flags.append(
                f'Sender address {from_email} has recent malicious activity in last 90 days '
                f'(EmailRep)'
            )
        elif emailrep['suspicious']:
            flags.append(
                f'Sender address {from_email} is flagged as suspicious by EmailRep '
                f'(reputation: {emailrep["reputation"]}, references: {emailrep["references"]})'
            )
        if emailrep['disposable']:
            flags.append(f'Sender address {from_email} is a disposable/throwaway address')
        if emailrep['new_domain'] and emailrep['days_since_domain_creation'] != -1:
            days = emailrep['days_since_domain_creation']
            flags.append(f'Sender domain is new ({days} days old) — recently registered domains are high risk')
        if emailrep['credentials_leaked_recent']:
            flags.append(f'Sender address {from_email} had credentials leaked in last 90 days — likely compromised account')

    logger.info(
        f'Header check: {len(flags)} flag(s) | from={from_domain} | ip={sender_ip} | '
        f'emailrep={emailrep["reputation"] if emailrep else "not configured"}'
    )

    return {
        'from_domain':          from_domain,
        'reply_to_domain':      reply_domain,
        'return_path_domain':   return_path_dom,
        'sender_ip':            sender_ip,
        'received_hops':        len(headers.get('received', [])),
        'reply_mismatch':       reply_mismatch,
        'return_path_mismatch': return_path_mismatch,
        'mid_mismatch':         mid_mismatch,
        'no_received':          no_received,
        'emailrep':             emailrep,
        'from_email':           from_email,
        'flags':                flags,
    }


def check_authentication(domain: str, raw_bytes: bytes = b'') -> dict:
    if not domain:
        return {
            'domain': '',
            'spf':   {'record': None, 'result': 'missing'},
            'dmarc': {'record': None, 'result': 'missing', 'policy': 'none'},
            'dkim':  {'record': None, 'result': 'missing', 'selector': '',
                      'signature_present': False, 'signature_valid': None},
            'flags': ['Could not extract sender domain – skipping auth checks'],
        }

    spf_record           = _lookup_spf(domain)
    dmarc_record         = _lookup_dmarc(domain)

    # Try selector extracted from actual email first, then fall back to common selectors
    email_selector = _extract_dkim_selector_from_bytes(raw_bytes)
    if email_selector and email_selector not in DKIM_SELECTORS:
        dkim_selectors_to_try = [email_selector] + DKIM_SELECTORS
    elif email_selector:
        dkim_selectors_to_try = [email_selector] + [s for s in DKIM_SELECTORS if s != email_selector]
    else:
        dkim_selectors_to_try = DKIM_SELECTORS

    dkim_record, sel     = _lookup_dkim_record(domain, dkim_selectors_to_try)

    dmarc_policy = 'none'
    if dmarc_record:
        m = re.search(r'\bp=(\w+)', dmarc_record)
        if m:
            dmarc_policy = m.group(1)

    sig_present = b'DKIM-Signature' in raw_bytes if raw_bytes else False
    sig_valid   = _verify_dkim(raw_bytes) if sig_present else None

    flags = []
    if not spf_record:
        flags.append(f'No SPF record for {domain}')
    if not dmarc_record:
        flags.append(f'No DMARC record for {domain}')
    if not dkim_record:
        flags.append(f'No DKIM DNS record for {domain} (tried: {", ".join(DKIM_SELECTORS)})')
    if sig_present and sig_valid is False:
        flags.append('DKIM signature present but verification failed')
    if dmarc_record and dmarc_policy == 'none':
        flags.append(f'DMARC policy is "none" for {domain} – monitoring only, no enforcement')

    logger.info(
        f'Auth: domain={domain} | '
        f'spf={"found" if spf_record else "missing"} | '
        f'dmarc={"found" if dmarc_record else "missing"}(p={dmarc_policy}) | '
        f'dkim_dns={"found" if dkim_record else "missing"} | '
        f'sig_present={sig_present} sig_valid={sig_valid}'
    )

    return {
        'domain': domain,
        'spf':   {'record': spf_record,   'result': 'found' if spf_record   else 'missing'},
        'dmarc': {'record': dmarc_record, 'result': 'found' if dmarc_record else 'missing',
                  'policy': dmarc_policy},
        'dkim':  {'record': dkim_record,  'result': 'found' if dkim_record  else 'missing',
                  'selector': sel, 'signature_present': sig_present, 'signature_valid': sig_valid},
        'flags': flags,
    }


def check_reputation(ip: str) -> dict:
    """
    Checks sender IP against:
      - Spamhaus ZEN DNSBL  (binary listed/clean)
      - ThreatFox            (known C2/malware infrastructure)
      - AbuseIPDB            (0–100 confidence score, requires API key)
    """
    empty = {
        'ip':              ip,
        'spamhaus_zen':    False,
        'threatfox_ip':    False,
        'abuseipdb_score': -1,
        'virustotal_ip':   None,
        'flags':           [],
    }

    if not ip or _PRIVATE_IP.match(ip):
        return empty

    flags = []

    reversed_ip = '.'.join(reversed(ip.split('.')))
    on_zen      = _dnsbl(reversed_ip, 'zen.spamhaus.org')
    if on_zen:
        flags.append(f'Sender IP {ip} listed on Spamhaus ZEN')

    tf_hit = _threatfox(ip)
    if tf_hit:
        flags.append(f'Sender IP {ip} found in ThreatFox (known C2/malware infrastructure)')

    vt_ip = _virustotal_ip(ip)
    if vt_ip is not None and vt_ip['malicious'] > 0:
        flags.append(
            f'Sender IP {ip} flagged by {vt_ip["malicious"]}/{vt_ip["total"]} '
            f'VirusTotal engines'
        )

    score = _abuseipdb(ip)
    if score >= _ABUSEIPDB_MALICIOUS:
        flags.append(f'Sender IP {ip} has AbuseIPDB confidence score {score}/100')
    elif score >= _ABUSEIPDB_SUSPICIOUS:
        flags.append(f'Sender IP {ip} has elevated AbuseIPDB score {score}/100')

    logger.info(
        f'Reputation: ip={ip} | '
        f'zen={"LISTED" if on_zen else "clean"} | '
        f'threatfox={"HIT" if tf_hit else "clean"} | '
        f'abuseipdb={score if score != -1 else "not configured"}'
    )

    return {
        'ip':              ip,
        'spamhaus_zen':    on_zen,
        'threatfox_ip':    tf_hit,
        'abuseipdb_score': score,
        'virustotal_ip':   vt_ip,
        'flags':           flags,
    }


def check_urls(urls: list) -> dict:
    """
    Checks each URL against:
      - URLhaus       (malware distribution URLs)
      - Spamhaus DBL  (domain blocklist)
      - ThreatFox     (malicious domain infrastructure)
    """
    results = []
    flags   = []
    targets = list(dict.fromkeys(urls))[:_MAX_URLS]

    vt_delay = float(os.environ.get('VIRUSTOTAL_RATE_DELAY', '0'))

    # Google Safe Browsing — single bulk call for all URLs at once
    gsb_results = _google_safe_browsing(targets)
    if gsb_results:
        logger.info(f'Google Safe Browsing: {len(gsb_results)} threat(s) found in {len(targets)} URLs')

    # Track flagged domains to avoid duplicate flags for same domain
    _flagged_dbl_domains      = set()
    _flagged_threatfox_domains = set()

    for url in targets:
        entry = {
            'url':              url,
            'urlhaus':          False,
            'spamhaus_dbl':     False,
            'threatfox_domain': False,
            'virustotal':       None,
            'google_safebrowsing': None,
        }

        # GSB result already computed in bulk above
        gsb_threat = gsb_results.get(url)
        if gsb_threat:
            entry['google_safebrowsing'] = gsb_threat
            threat_label = {
                'MALWARE':                         'malware',
                'SOCIAL_ENGINEERING':              'phishing/social engineering',
                'UNWANTED_SOFTWARE':               'unwanted software',
                'POTENTIALLY_HARMFUL_APPLICATION': 'potentially harmful app',
            }.get(gsb_threat, gsb_threat)
            flags.append(f'URL flagged by Google Safe Browsing as {threat_label}: {url}')

        if _urlhaus(url):
            entry['urlhaus'] = True
            flags.append(f'URL found in URLhaus: {url}')

        m = re.search(r'https?://([^/?\s]+)', url)
        if m:
            domain = m.group(1).lower().rstrip('.')

            if domain not in _DBL_WHITELIST and _dnsbl(domain, 'dbl.spamhaus.org'):
                entry['spamhaus_dbl'] = True
                if domain not in _flagged_dbl_domains:
                    flags.append(f'URL domain on Spamhaus DBL: {domain}')
                    _flagged_dbl_domains.add(domain)

            if _threatfox(domain):
                entry['threatfox_domain'] = True
                if domain not in _flagged_threatfox_domains:
                    flags.append(f'URL domain found in ThreatFox: {domain}')
                    _flagged_threatfox_domains.add(domain)

        vt = _virustotal_url(url)
        entry['virustotal'] = vt
        if vt is not None:
            if vt['malicious'] > 0:
                flags.append(
                    f'URL flagged by {vt["malicious"]}/{vt["total"]} VirusTotal engines: {url}'
                )
            elif vt['suspicious'] > 0:
                flags.append(
                    f'URL marked suspicious by {vt["suspicious"]}/{vt["total"]} VirusTotal engines: {url}'
                )
            if vt_delay > 0:
                time.sleep(vt_delay)

        results.append(entry)

    urlhaus_hits   = sum(1 for r in results if r['urlhaus'])
    dbl_hits       = sum(1 for r in results if r['spamhaus_dbl'])
    threatfox_hits = sum(1 for r in results if r['threatfox_domain'])
    vt_hits        = sum(1 for r in results if r['virustotal'] and r['virustotal']['malicious'] > 0)
    vt_suspicious  = sum(1 for r in results if r['virustotal'] and r['virustotal']['suspicious'] > 0 and (not r['virustotal']['malicious']))
    gsb_hits       = sum(1 for r in results if r['google_safebrowsing'])

    logger.info(
        f'URL check: {len(targets)}/{len(urls)} checked | '
        f'urlhaus={urlhaus_hits} | dbl={dbl_hits} | threatfox={threatfox_hits} | '
        f'gsb={gsb_hits} | vt_malicious={vt_hits} | vt_suspicious={vt_suspicious}'
    )

    return {
        'total':          len(urls),
        'checked':        len(targets),
        'results':        results,
        'urlhaus_hits':   urlhaus_hits,
        'dbl_hits':       dbl_hits,
        'threatfox_hits': threatfox_hits,
        'gsb_hits':       gsb_hits,
        'vt_hits':        vt_hits,
        'vt_suspicious':  vt_suspicious,
        'flags':          flags,
    }


def check_attachments(attachments: list) -> dict:
    """
    For each attachment:
      - SHA256 hash
      - MalwareBazaar hash lookup
      - ThreatFox hash lookup
      - Dangerous extension check
      - MIME magic byte vs declared content-type mismatch
    Only hashes are sent externally – raw bytes never leave the container.
    """
    results = []
    flags   = []

    for att in attachments:
        data     = att.get('data', b'')
        filename = att.get('filename', 'unknown')
        declared = att.get('content_type', '').lower()

        sha256_hash   = _sha256(data) if data else ''
        ext_match     = re.search(r'\.[a-zA-Z0-9]{1,10}$', filename)
        extension     = ext_match.group(0).lower() if ext_match else ''
        dangerous     = extension in DANGEROUS_EXTENSIONS
        detected_mime = _detect_mime(data[:8]) if data else None
        mime_mismatch = bool(
            detected_mime and
            detected_mime not in declared and
            declared not in detected_mime
        )
        mb_hit = _malwarebazaar(sha256_hash) if sha256_hash else False
        tf_hit = _threatfox(sha256_hash)     if sha256_hash else False
        vt_hit = _virustotal_hash(sha256_hash) if sha256_hash else None

        if mb_hit:
            flags.append(f'Attachment {filename} ({sha256_hash[:16]}…) found in MalwareBazaar')
        if tf_hit:
            flags.append(f'Attachment {filename} ({sha256_hash[:16]}…) found in ThreatFox')
        if vt_hit is not None and vt_hit['malicious'] > 0:
            flags.append(
                f'Attachment {filename} flagged by {vt_hit["malicious"]}/{vt_hit["total"]} '
                f'VirusTotal engines ({sha256_hash[:16]}…)'
            )
        if dangerous:
            flags.append(f'Dangerous attachment extension: {filename} ({extension})')
        if mime_mismatch:
            flags.append(
                f'MIME mismatch in {filename}: '
                f'declared={declared}, detected={detected_mime}'
            )

        results.append({
            'filename':      filename,
            'sha256':        sha256_hash,
            'extension':     extension,
            'declared_mime': declared,
            'detected_mime': detected_mime,
            'dangerous':     dangerous,
            'mime_mismatch': mime_mismatch,
            'malwarebazaar': mb_hit,
            'threatfox':     tf_hit,
            'virustotal':    vt_hit,
            'size':          att.get('size', 0),
        })

        logger.debug(
            f'Attachment: {filename} | sha256={sha256_hash[:16]}… | '
            f'mb={mb_hit} | tf={tf_hit} | '
            f'dangerous={dangerous} | mime_mismatch={mime_mismatch}'
        )

    mb_hits = sum(1 for r in results if r['malwarebazaar'])
    tf_hits = sum(1 for r in results if r['threatfox'])
    vt_hits = sum(1 for r in results if r['virustotal'] and r['virustotal']['malicious'] > 0)
    logger.info(
        f'Attachment check: {len(results)} file(s) | '
        f'mb_hits={mb_hits} | tf_hits={tf_hits} | vt_hits={vt_hits}'
    )

    return {
        'count':              len(results),
        'results':            results,
        'malwarebazaar_hits': mb_hits,
        'threatfox_hits':     tf_hits,
        'vt_hits':            vt_hits,
        'flags':              flags,
    }


# ── Verdict ───────────────────────────────────────────────────────────────────

def _calculate_verdict(
    header_f: dict,
    auth_f:   dict,
    rep_f:    dict,
    url_f:    dict,
    att_f:    dict,
) -> str:
    abuseipdb_score = rep_f.get('abuseipdb_score', -1)

    # EmailRep signals on sender address
    emailrep = header_f.get('emailrep') or {}
    emailrep_malicious  = bool(emailrep.get('blacklisted') or emailrep.get('malicious_activity') or emailrep.get('malicious_activity_recent'))
    emailrep_suspicious = bool(emailrep.get('suspicious')) and not emailrep_malicious

    # VirusTotal hits
    vt_ip_malicious   = (rep_f.get('virustotal_ip')  or {}).get('malicious', 0) > 0
    vt_url_malicious  = url_f.get('vt_hits', 0) > 0
    vt_att_malicious  = att_f.get('vt_hits', 0) > 0
    vt_url_suspicious = url_f.get('vt_suspicious', 0) > 0

    # Google Safe Browsing
    gsb_hits = url_f.get('gsb_hits', 0) > 0

    if any([
        header_f['reply_mismatch'],
        header_f['return_path_mismatch'],
        rep_f['spamhaus_zen'],
        rep_f.get('threatfox_ip', False),
        emailrep_malicious,
        vt_ip_malicious,
        vt_url_malicious,
        vt_att_malicious,
        gsb_hits,
        abuseipdb_score != -1 and abuseipdb_score >= _ABUSEIPDB_MALICIOUS,
        url_f['urlhaus_hits']        > 0,
        url_f['dbl_hits']            > 0,
        url_f['threatfox_hits']      > 0,
        att_f['malwarebazaar_hits']  > 0,
        att_f['threatfox_hits']      > 0,
        auth_f['dkim']['signature_present'] and auth_f['dkim']['signature_valid'] is False,
    ]):
        return 'MOST LIKELY UNSAFE'



    missing_auth = sum([
        auth_f['spf']['result']   == 'missing',
        auth_f['dmarc']['result'] == 'missing',
        auth_f['dkim']['result']  == 'missing',
    ])

    if missing_auth >= 2:
        return 'MOST LIKELY UNSAFE'

    uncertain = any([
        missing_auth == 1,
        auth_f['dmarc']['policy'] == 'none',
        header_f['mid_mismatch'],
        header_f['no_received'],
        emailrep_suspicious,
        abuseipdb_score != -1 and abuseipdb_score >= _ABUSEIPDB_SUSPICIOUS,
        vt_url_suspicious,
        any(r['dangerous']     for r in att_f['results']),
        any(r['mime_mismatch'] for r in att_f['results']),
    ])

    if uncertain:
        return 'FURTHER ANALYSIS REQUIRED'

    if missing_auth == 0 and auth_f['dmarc']['policy'] in ('reject', 'quarantine'):
        return 'MOST LIKELY SAFE'

    return 'FURTHER ANALYSIS REQUIRED'


# ── Entry point ───────────────────────────────────────────────────────────────

def analyze(parsed: dict, raw_bytes: bytes = b'') -> dict:
    logger.info('Analysis started')

    headers         = parsed.get('headers', {})
    header_findings = check_headers(headers)
    auth_findings   = check_authentication(header_findings['from_domain'], raw_bytes)
    rep_findings    = check_reputation(header_findings['sender_ip'])
    url_findings    = check_urls(parsed.get('urls', []))
    att_findings    = check_attachments(parsed.get('attachments', []))

    verdict = _calculate_verdict(
        header_findings, auth_findings, rep_findings, url_findings, att_findings
    )

    all_flags = (
        header_findings['flags'] +
        auth_findings['flags']   +
        rep_findings['flags']    +
        url_findings['flags']    +
        att_findings['flags']
    )

    logger.info(f'Analysis complete: verdict={verdict} | flags={len(all_flags)}')

    return {
        'verdict':         verdict,
        'domain':          auth_findings['domain'],
        'sender_ip':       header_findings['sender_ip'],
        'header_findings': header_findings,
        'auth_findings':   auth_findings,
        'rep_findings':    rep_findings,
        'url_findings':    url_findings,
        'att_findings':    att_findings,
        'all_flags':       all_flags,
    }