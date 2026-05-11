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


def _lookup_dkim_record(domain: str) -> tuple[str | None, str]:
    for selector in DKIM_SELECTORS:
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
            if mid_domain != from_domain:
                mid_mismatch = True
                flags.append(f'Message-ID domain ({mid_domain}) differs from From ({from_domain})')

    no_received = not headers.get('received')
    if no_received:
        flags.append('No Received headers – possible direct injection')

    x_mailer = headers.get('x_mailer', '').lower()
    if x_mailer and any(t in x_mailer for t in _SPAM_TOOLS):
        flags.append(f'Suspicious X-Mailer: {headers["x_mailer"]}')

    logger.info(f'Header check: {len(flags)} flag(s) | from={from_domain} | ip={sender_ip}')

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
    dkim_record, sel     = _lookup_dkim_record(domain)

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
        'ip':             ip,
        'spamhaus_zen':   False,
        'threatfox_ip':   False,
        'abuseipdb_score': -1,
        'flags':          [],
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

    for url in targets:
        entry = {
            'url':            url,
            'urlhaus':        False,
            'spamhaus_dbl':   False,
            'threatfox_domain': False,
        }

        if _urlhaus(url):
            entry['urlhaus'] = True
            flags.append(f'URL found in URLhaus: {url}')

        m = re.search(r'https?://([^/?\s]+)', url)
        if m:
            domain = m.group(1).lower().rstrip('.')

            if _dnsbl(domain, 'dbl.spamhaus.org'):
                entry['spamhaus_dbl'] = True
                flags.append(f'URL domain on Spamhaus DBL: {domain}')

            if _threatfox(domain):
                entry['threatfox_domain'] = True
                flags.append(f'URL domain found in ThreatFox: {domain}')

        results.append(entry)

    urlhaus_hits   = sum(1 for r in results if r['urlhaus'])
    dbl_hits       = sum(1 for r in results if r['spamhaus_dbl'])
    threatfox_hits = sum(1 for r in results if r['threatfox_domain'])

    logger.info(
        f'URL check: {len(targets)}/{len(urls)} checked | '
        f'urlhaus={urlhaus_hits} | dbl={dbl_hits} | threatfox={threatfox_hits}'
    )

    return {
        'total':          len(urls),
        'checked':        len(targets),
        'results':        results,
        'urlhaus_hits':   urlhaus_hits,
        'dbl_hits':       dbl_hits,
        'threatfox_hits': threatfox_hits,
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

        if mb_hit:
            flags.append(f'Attachment {filename} ({sha256_hash[:16]}…) found in MalwareBazaar')
        if tf_hit:
            flags.append(f'Attachment {filename} ({sha256_hash[:16]}…) found in ThreatFox')
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
            'size':          att.get('size', 0),
        })

        logger.debug(
            f'Attachment: {filename} | sha256={sha256_hash[:16]}… | '
            f'mb={mb_hit} | tf={tf_hit} | '
            f'dangerous={dangerous} | mime_mismatch={mime_mismatch}'
        )

    mb_hits = sum(1 for r in results if r['malwarebazaar'])
    tf_hits = sum(1 for r in results if r['threatfox'])
    logger.info(
        f'Attachment check: {len(results)} file(s) | '
        f'mb_hits={mb_hits} | tf_hits={tf_hits}'
    )

    return {
        'count':              len(results),
        'results':            results,
        'malwarebazaar_hits': mb_hits,
        'threatfox_hits':     tf_hits,
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

    if any([
        header_f['reply_mismatch'],
        header_f['return_path_mismatch'],
        rep_f['spamhaus_zen'],
        rep_f['threatfox_ip'],
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
        abuseipdb_score != -1 and abuseipdb_score >= _ABUSEIPDB_SUSPICIOUS,
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