# src/reporter.py
# Generates a structured security analysis report.
# Structure: metadata → checks (in order) → flags → sources → verdict
#
# Delivery:
#   1. Printed to terminal
#   2. SMTP (optional): REPORT_SMTP_HOST, REPORT_SMTP_PORT, REPORT_FROM_ADDR
 
import os
import smtplib
import textwrap
from datetime import datetime, timezone
from email.mime.text import MIMEText
from src.logger import get_logger

logger      = get_logger(__name__)
try:
    from importlib.metadata import version as _pkg_version
    _VERSION = _pkg_version('postmortemcli')
except Exception:
    _VERSION = '0.2.16-beta'
_REPORT_DIR = '/tmp/postmortem/reports'
_W          = 64   # line width


# ── Formatting ────────────────────────────────────────────────────────────────

def _rule(char='─'): return char * _W

def _title(text, char='═'):
    return f'{char * _W}\n  {text}\n{char * _W}'

def _section(text):
    return f'\n{_rule()}\n  {text}\n{_rule()}'

def _row(label, value, w=22):
    return f'  {label:<{w}} {value}'

def _check_row(label, value, w=26):
    return f'    {label:<{w}} {value}'

def _wrap(text, indent=4):
    return textwrap.fill(
        text,
        width=_W - indent,
        initial_indent=' ' * indent,
        subsequent_indent=' ' * (indent + 2),
    )

def _verdict_block(verdict):
    icons = {
        'MOST LIKELY SAFE':          '✓',
        'MOST LIKELY UNSAFE':        '✗',
        'FURTHER ANALYSIS REQUIRED': '?',
    }
    icon = icons.get(verdict, '?')
    bar  = '═' * _W
    mid  = f'  {icon}  {verdict}'
    return f'\n{bar}\n{mid}\n{bar}'


# ── Sections ──────────────────────────────────────────────────────────────────

def _msg_section(parsed):
    h = parsed['headers']
    out = [_section('ORIGINAL MESSAGE')]
    out.append(_row('From:',        h.get('from', '')        or '(none)'))
    out.append(_row('To:',          h.get('to', '')          or '(none)'))
    out.append(_row('Subject:',     h.get('subject', '')     or '(none)'))
    out.append(_row('Date:',        h.get('date', '')        or '(none)'))
    out.append(_row('Message-ID:',  h.get('message_id', '')  or '(none)'))
    out.append(_row('Reply-To:',    h.get('reply_to', '')    or '(not set)'))
    out.append(_row('Return-Path:', h.get('return_path', '') or '(not set)'))
    received = h.get('received', [])
    out.append(f'\n  Received chain  ({len(received)} hop(s)):')
    if received:
        for i, hop in enumerate(received, 1):
            out.append(f'    [{i}] {hop[:68]}{"..." if len(hop) > 68 else ""}')
    else:
        out.append('    (none)')
    return '\n'.join(out)


def _headers_section(hf):
    out = [_section('HEADER ANALYSIS')]
    out.append(_row('Sender domain:',   hf['from_domain']        or '(unknown)'))
    out.append(_row('Reply-To domain:', hf['reply_to_domain']    or '(not set)'))
    out.append(_row('Return-Path:',     hf['return_path_domain'] or '(not set)'))
    out.append(_row('Sender IP:',       hf['sender_ip']          or '(not found — no Received headers)'))
    out.append(_row('Received hops:',   str(hf['received_hops'])))
    out.append('\n  Checks:')
    out.append(_check_row('Reply-To mismatch:',    '⚠  YES' if hf['reply_mismatch']       else '✓  no'))
    out.append(_check_row('Return-Path mismatch:', '⚠  YES' if hf['return_path_mismatch'] else '✓  no'))
    out.append(_check_row('Message-ID mismatch:',  '⚠  YES' if hf['mid_mismatch']         else '✓  no'))
    out.append(_check_row('Missing Received chain:','⚠  YES' if hf['no_received']          else '✓  no'))

    er = hf.get('emailrep')
    email = hf.get('from_email', '')
    out.append(f'\n  EmailRep  (sender: {email or "unknown"}):')
    if er is None:
        out.append(_check_row('Status:', '–  unavailable  (rate limited or key not configured)'))
    else:
        rep_icon = '⚠ ' if er['suspicious'] or er['blacklisted'] or er['malicious_activity'] else '✓ '
        out.append(_check_row('Reputation:',       f'{rep_icon} {er["reputation"]}  ({er["references"]} references)'))
        out.append(_check_row('Blacklisted:',      '⚠  YES' if er['blacklisted']               else '✓  no'))
        out.append(_check_row('Malicious activity:','⚠  YES' if er['malicious_activity']        else '✓  no'))
        out.append(_check_row('Recent malicious:', '⚠  YES' if er['malicious_activity_recent']  else '✓  no'))
        out.append(_check_row('Spam:',             '⚠  YES' if er['spam']                       else '✓  no'))
        out.append(_check_row('Spoofable:',        '⚠  YES' if er['spoofable']                  else '✓  no'))
        out.append(_check_row('Disposable address:','⚠  YES' if er['disposable']                else '✓  no'))
        if er['new_domain'] and er['days_since_domain_creation'] != -1:
            out.append(_check_row('Domain age:', f'⚠  {er["days_since_domain_creation"]} days — newly registered'))
        if er['credentials_leaked']:
            leaked = '(RECENT — likely compromised)' if er['credentials_leaked_recent'] else '(historical)'
            out.append(_check_row('Credentials leaked:', f'⚠  YES  {leaked}'))

    return '\n'.join(out)


def _auth_section(af):
    out  = [_section(f'AUTHENTICATION  (domain: {af["domain"] or "unknown"})')]
    spf   = af['spf']
    dmarc = af['dmarc']
    dkim  = af['dkim']

    out.append('\n  SPF:')
    out.append(_check_row('Result:', spf['result']))
    if spf['record']:
        out.append(_check_row('Record:', ''))
        out.append(_wrap(spf['record'], indent=6))
    else:
        out.append(_check_row('Record:', '(none found)'))

    out.append('\n  DMARC:')
    out.append(_check_row('Result:', dmarc['result']))
    out.append(_check_row('Policy:', dmarc['policy']))
    if dmarc['record']:
        out.append(_check_row('Record:', ''))
        out.append(_wrap(dmarc['record'], indent=6))
    else:
        out.append(_check_row('Record:', '(none found)'))

    out.append('\n  DKIM:')
    out.append(_check_row('DNS record:', dkim['result']))
    if dkim['selector']:
        out.append(_check_row('Selector found:', dkim['selector']))
    out.append(_check_row('Signature in email:', 'yes' if dkim['signature_present'] else 'no'))
    if dkim['signature_present']:
        if dkim['signature_valid'] is True:
            out.append(_check_row('Signature valid:', '✓  yes — cryptographically verified'))
        elif dkim['signature_valid'] is False:
            out.append(_check_row('Signature valid:', '⚠  NO — verification failed'))
        else:
            out.append(_check_row('Signature valid:', '?  unverified'))
    return '\n'.join(out)


def _rep_section(rf):
    ip  = rf['ip']
    out = [_section(f'IP REPUTATION  (sender IP: {ip or "not found"})')]

    if not ip:
        out.append('\n  No sender IP in Received headers — reputation checks skipped.')
        out.append('  Note: some email clients strip Received headers when saving .eml files.')
        return '\n'.join(out)

    score = rf.get('abuseipdb_score', -1)
    out.append('\n  Checks against live threat intelligence:')
    out.append(_check_row('Spamhaus ZEN DNSBL:', '⚠  LISTED' if rf['spamhaus_zen']      else '✓  clean'))
    out.append(_check_row('ThreatFox IOC:',      '⚠  HIT'    if rf.get('threatfox_ip')  else '✓  clean'))
    vt_ip = rf.get('virustotal_ip')
    if vt_ip is None:
        out.append(_check_row('VirusTotal IP:', '–  not configured  (set VIRUSTOTAL_API_KEY)'))
    elif vt_ip.get('note') == 'not in database':
        out.append(_check_row('VirusTotal IP:', f'?  not in database'))
    elif vt_ip['malicious'] > 0:
        out.append(_check_row('VirusTotal IP:', f'⚠  {vt_ip["malicious"]}/{vt_ip["total"]} engines flagged'))
    else:
        out.append(_check_row('VirusTotal IP:', f'✓  clean  (0/{vt_ip["total"]} engines)'))

    if score == -1:
        out.append(_check_row('AbuseIPDB:', '–  not configured  (set ABUSEIPDB_API_KEY)'))
    elif score >= 80:
        out.append(_check_row('AbuseIPDB:', f'⚠  {score}/100  (≥80 = malicious threshold)'))
    elif score >= 25:
        out.append(_check_row('AbuseIPDB:', f'?  {score}/100  (≥25 = suspicious threshold)'))
    else:
        out.append(_check_row('AbuseIPDB:', f'✓  {score}/100  (clean)'))
    return '\n'.join(out)


def _urls_section(url_f, urls):
    total   = url_f['total']
    checked = url_f['checked']
    out     = [_section(f'URL ANALYSIS  ({total} found, {checked} checked)')]

    if not urls:
        out.append('\n  No URLs found in message body.')
        return '\n'.join(out)

    rmap = {r['url']: r for r in url_f['results']}
    for url in urls:
        r     = rmap.get(url, {})
        short = url[:60] + ('...' if len(url) > 60 else '')
        out.append(f'\n  {short}')
        out.append(_check_row('URLhaus:',     '⚠  LISTED' if r.get('urlhaus')          else '✓  clean', 16))
        out.append(_check_row('Spamhaus DBL:','⚠  LISTED' if r.get('spamhaus_dbl')     else '✓  clean', 16))
        out.append(_check_row('ThreatFox:',   '⚠  HIT'    if r.get('threatfox_domain') else '✓  clean', 16))
        vt = r.get('virustotal')
        if vt is None:
            out.append(_check_row('VirusTotal:', '–  not configured', 16))
        elif vt.get('note') == 'not in database':
            out.append(_check_row('VirusTotal:', '?  not in database', 16))
        elif vt['malicious'] > 0:
            out.append(_check_row('VirusTotal:', f'⚠  {vt["malicious"]}/{vt["total"]} engines flagged', 16))
        elif vt['suspicious'] > 0:
            out.append(_check_row('VirusTotal:', f'?  {vt["suspicious"]}/{vt["total"]} engines suspicious', 16))
        else:
            out.append(_check_row('VirusTotal:', f'✓  clean  (0/{vt["total"]} engines)', 16))
        gsb = r.get('google_safebrowsing')
        if gsb is None and not os.environ.get('GOOGLE_SAFE_BROWSING_KEY'):
            out.append(_check_row('Google SafeBrowsing:', '–  not configured', 16))
        elif gsb:
            label = {'MALWARE': 'malware', 'SOCIAL_ENGINEERING': 'phishing', 'UNWANTED_SOFTWARE': 'unwanted software'}.get(gsb, gsb)
            out.append(_check_row('Google SafeBrowsing:', f'⚠  FLAGGED  ({label})', 16))
        elif gsb == '':
            out.append(_check_row('Google SafeBrowsing:', '–  not checked', 16))
        else:
            out.append(_check_row('Google SafeBrowsing:', '✓  clean', 16))
    return '\n'.join(out)


def _att_section(att_f):
    out = [_section(f'ATTACHMENT ANALYSIS  ({att_f["count"]} file(s))')]

    if not att_f['results']:
        out.append('\n  No attachments found.')
        return '\n'.join(out)

    for att in att_f['results']:
        sha = att['sha256']
        out.append(f'\n  {att["filename"]}')
        out.append(_check_row('Size:',          f'{att["size"]:,} bytes',                      18))
        out.append(_check_row('Extension:',     att['extension']              or '(none)',     18))
        out.append(_check_row('Declared MIME:', att['declared_mime']          or '(none)',     18))
        out.append(_check_row('Detected MIME:', att['detected_mime']          or '(unknown)',  18))
        out.append(_check_row('SHA256:',        (sha[:48] + '…') if sha else '(empty)', 18))
        out.append('')
        out.append(_check_row('Dangerous ext:',  '⚠  YES' if att['dangerous']     else '✓  no',    18))
        out.append(_check_row('MIME mismatch:',  '⚠  YES' if att['mime_mismatch'] else '✓  no',    18))
        out.append(_check_row('MalwareBazaar:',  '⚠  HIT' if att['malwarebazaar'] else '✓  clean', 18))
        out.append(_check_row('ThreatFox:',      '⚠  HIT' if att.get('threatfox') else '✓  clean', 18))
    return '\n'.join(out)


def _flags_section(all_flags):
    out = [_section(f'FLAGS  ({len(all_flags)} raised)')]
    if not all_flags:
        out.append('\n  No flags raised.')
    else:
        out.append('')
        for i, flag in enumerate(all_flags, 1):
            line = textwrap.fill(
                f'[{i:02d}] ⚠  {flag}',
                width=_W - 2,
                initial_indent='  ',
                subsequent_indent='       ',
            )
            out.append(line)
    return '\n'.join(out)


def _sources_section():
    out = [_section('THREAT INTELLIGENCE SOURCES')]
    out.append('')
    for name, kind, purpose, key in [
        ('Spamhaus ZEN',        'DNSBL', 'Sender IP blocklist',              'no key'),
        ('Spamhaus DBL',        'DNSBL', 'URL domain blocklist',             'no key'),
        ('URLhaus',             'API',   'Malicious URL database',           'ABUSE_CH_API_KEY'),
        ('MalwareBazaar',       'API',   'Malware hash database (SHA256)',   'ABUSE_CH_API_KEY'),
        ('ThreatFox',           'API',   'IOC: IPs, domains, hashes',        'ABUSE_CH_API_KEY'),
        ('AbuseIPDB',           'API',   'IP abuse confidence 0–100',        'ABUSEIPDB_API_KEY'),
        ('VirusTotal',          'API',   'URL/file/IP — 70+ AV engines',     'VIRUSTOTAL_API_KEY'),
        ('EmailRep',            'API',   'Sender email address reputation',  'pending approval'),
        ('Google SafeBrowsing', 'API',   'URL phishing/malware check',       'GOOGLE_SAFE_BROWSING_KEY'),
    ]:
        out.append(f'  {name:<16} [{kind:<4}]  {purpose:<36} {key}')
    out.append('')
    out.append('  GDPR: IP addresses and SHA256 hashes sent to all sources.')
    out.append('  EmailRep receives the sender email address (personal data) for')
    out.append('  security analysis under legitimate interest — not stored locally.')
    out.append('  Google Safe Browsing receives actual URL strings (not personal data).')
    out.append('  No email body content, names, or attachment data transmitted.')
    return '\n'.join(out)


# ── Verdict explanation ───────────────────────────────────────────────────────

def _verdict_explanation(result: dict) -> str:
    """
    Produces a plain-language explanation of exactly why the verdict was reached.
    """
    verdict = result["verdict"]
    hf      = result["header_findings"]
    af      = result["auth_findings"]
    rf      = result["rep_findings"]
    url_f   = result["url_findings"]
    att_f   = result["att_findings"]
    score   = rf.get("abuseipdb_score", -1)

    reasons = []

    # MOST LIKELY UNSAFE triggers
    if hf["reply_mismatch"]:
        reasons.append(f'Reply-To domain ({hf["reply_to_domain"]}) does not match the From domain ({hf["from_domain"]}). This is a classic BEC/phishing indicator — replies go to the attacker, not the apparent sender.')
    if hf["return_path_mismatch"]:
        reasons.append(f'Return-Path domain ({hf["return_path_domain"]}) does not match From ({hf["from_domain"]}). Bounced messages return to a different address than the claimed sender.')
    if rf["spamhaus_zen"]:
        reasons.append(f'Sender IP {rf["ip"]} is listed on Spamhaus ZEN — a live blocklist of known spam sources, open relays, and compromised hosts.')
    if rf.get("threatfox_ip"):
        reasons.append(f'Sender IP {rf["ip"]} is in ThreatFox — associated with known malware C2 infrastructure or botnet activity.')
    if score != -1 and score >= 80:
        reasons.append(f'Sender IP {rf["ip"]} has an AbuseIPDB confidence score of {score}/100 — reported as malicious by the security community.')
    if url_f["urlhaus_hits"] > 0:
        reasons.append(f'{url_f["urlhaus_hits"]} URL(s) found in URLhaus — a database of URLs actively distributing malware.')
    if url_f["dbl_hits"] > 0:
        reasons.append(f'{url_f["dbl_hits"]} URL domain(s) listed on Spamhaus DBL — known spam or phishing domains.')
    if url_f["threatfox_hits"] > 0:
        reasons.append(f'{url_f["threatfox_hits"]} URL domain(s) found in ThreatFox — associated with malware infrastructure.')
    if att_f["malwarebazaar_hits"] > 0:
        reasons.append(f'{att_f["malwarebazaar_hits"]} attachment(s) matched in MalwareBazaar by SHA256 hash — confirmed malware samples.')
    if att_f["threatfox_hits"] > 0:
        reasons.append(f'{att_f["threatfox_hits"]} attachment hash(es) found in ThreatFox — associated with known malware.')
    if url_f.get("vt_hits", 0) > 0:
        reasons.append(f'{url_f["vt_hits"]} URL(s) flagged as malicious by VirusTotal — confirmed across multiple antivirus engines.')
    if url_f.get("gsb_hits", 0) > 0:
        reasons.append(f'{url_f["gsb_hits"]} URL(s) flagged by Google Safe Browsing — the same database used by Chrome and Firefox to block phishing and malware sites.')
    er = hf.get("emailrep") or {}
    if er.get("blacklisted") or er.get("malicious_activity"):
        reasons.append(f'Sender address {hf.get("from_email","")} is blacklisted or has documented malicious activity according to EmailRep (reputation: {er.get("reputation","unknown")}).')
    elif er.get("malicious_activity_recent"):
        reasons.append(f'Sender address {hf.get("from_email","")} had malicious activity in the last 90 days (EmailRep) — possible compromised or throwaway account.')
    if att_f.get("vt_hits", 0) > 0:
        reasons.append(f'{att_f["vt_hits"]} attachment(s) flagged by VirusTotal — confirmed malware by multiple engines.')
    vt_ip = rf.get("virustotal_ip")
    if vt_ip and vt_ip.get("malicious", 0) > 0:
        reasons.append(f'Sender IP {rf["ip"]} flagged by {vt_ip["malicious"]}/{vt_ip["total"]} VirusTotal engines.')
    if af["dkim"]["signature_present"] and af["dkim"]["signature_valid"] is False:
        reasons.append("DKIM signature is present but cryptographic verification failed — the message was tampered with after signing, or the signature is forged.")

    missing = sum([
        af["spf"]["result"]   == "missing",
        af["dmarc"]["result"] == "missing",
        af["dkim"]["result"]  == "missing",
    ])
    if missing >= 2:
        names = [n for n, k in [("SPF", "spf"), ("DMARC", "dmarc"), ("DKIM", "dkim")]
                 if af[k]["result"] == "missing"]
        reasons.append(f'{", ".join(names)} are all missing — the sender domain has no email authentication configured, making spoofing trivially easy.')

    # FURTHER ANALYSIS REQUIRED triggers
    if verdict == "FURTHER ANALYSIS REQUIRED":
        if missing == 1:
            name = next(n for n, k in [("SPF","spf"),("DMARC","dmarc"),("DKIM","dkim")] if af[k]["result"]=="missing")
            reasons.append(f'{name} record is missing — partial authentication leaves the domain open to spoofing.')
        if af["dmarc"]["policy"] == "none":
            reasons.append(f'DMARC policy is set to "none" — the domain owner monitors failures but does not enforce rejection or quarantine. Failed authentication is not acted upon.')
        if hf["mid_mismatch"]:
            reasons.append(f'Message-ID domain does not match the sender domain — may indicate routing through a third-party service or a spoofed header.')
        if hf["no_received"]:
            reasons.append("No Received headers found — the email may have been injected directly or headers were stripped, making routing analysis impossible.")
        if score != -1 and score >= 25:
            reasons.append(f'Sender IP {rf["ip"]} has an AbuseIPDB score of {score}/100 — elevated abuse reports warrant further investigation.')
        for att in att_f["results"]:
            if att["dangerous"]:
                reasons.append(f'Attachment "{att["filename"]}" has a dangerous extension ({att["extension"]}) — commonly used to deliver malware.')
            if att["mime_mismatch"]:
                reasons.append(f'Attachment "{att["filename"]}" declared MIME type ({att["declared_mime"]}) does not match actual file content ({att["detected_mime"]}) — possible extension spoofing.')

    if not reasons:
        return "  No specific risk factors identified. Verdict based on absence of strong positive authentication signals."

    out = []
    for i, r in enumerate(reasons, 1):
        wrapped = textwrap.fill(
            f"[{i}] {r}",
            width=_W - 2,
            initial_indent="  ",
            subsequent_indent="     ",
        )
        out.append(wrapped)
    return "\n".join(out)


# ── Entry point ───────────────────────────────────────────────────────────────

def _report_id(now_str: str) -> str:
    """Generates a unique report ID from timestamp: PMRT-20260511-162121"""
    ts = now_str.replace('-', '').replace(':', '').replace(' ', '-')[:15]
    return f'PMRT-{ts}'


def generate_report(parsed: dict, result: dict) -> str:
    now       = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    verdict   = result['verdict']
    report_id = _report_id(now)

    explanation = _verdict_explanation(result)

    # ── Report cover ──────────────────────────────────────────────
    B = '█'
    cover = [
        '',
        B * _W,
        B * _W,
        f'{B}{"POSTMORTEM — EMAIL SECURITY ANALYSIS":^{_W-2}}{B}',
        f'{B}{"POSTMORTEM ANALYSIS REPORT":^{_W-2}}{B}',
        B * _W,
        B * _W,
        '',
        f'  Report ID:      {report_id}',
        f'  Generated:      {now}',
        f'  Tool:           PostmortemCLI {_VERSION}',
        f'  Classification: SECURITY ANALYSIS — HANDLE ACCORDINGLY',
        f'  Retention:      NO DATA RETAINED — STATELESS ANALYSIS',
        '',
        _rule(),
    ]

    # ── Body ──────────────────────────────────────────────────────
    body = [
        _msg_section(parsed),
        _headers_section(result['header_findings']),
        _auth_section(result['auth_findings']),
        _rep_section(result['rep_findings']),
        _urls_section(result['url_findings'], parsed.get('urls', [])),
        _att_section(result['att_findings']),
        _flags_section(result['all_flags']),
        _sources_section(),
        _section(f'VERDICT: {verdict}'),
        f'\n{explanation}',
        _verdict_block(verdict),
    ]

    # ── Report footer ─────────────────────────────────────────────
    footer = [
        '',
        _rule(),
        f'  Report ID:   {report_id}',
        f'  Closed:      {now}',
        f'  Tool:        PostmortemCLI {_VERSION}',
        f'  Statement:   No email content, body text, attachment data, or personal',
        f'               information was retained or transmitted beyond what is',
        f'               documented in the Threat Intelligence Sources section above.',
        _rule(),
        '',
    ]

    text = '\n'.join(cover + body + footer)
    logger.info(f'Report generated | id={report_id} | verdict={verdict} | flags={len(result["all_flags"])}')
    return text


def save_report(report: str) -> str:
    os.makedirs(_REPORT_DIR, exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(_REPORT_DIR, f'report_{ts}.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(report)
    logger.info(f'Report saved → {path}')
    return path


def send_report(to_addr: str, report: str) -> bool:
    if not to_addr:
        logger.warning('SMTP send skipped — no recipient address')
        return False
    host      = os.environ.get('REPORT_SMTP_HOST', 'localhost')
    port      = int(os.environ.get('REPORT_SMTP_PORT', '25'))
    from_addr = os.environ.get('REPORT_FROM_ADDR', 'postmortem@localhost')
    msg            = MIMEText(report, 'plain', 'utf-8')
    msg['Subject'] = '[PostmortemCLI] Security Analysis Report'
    msg['From']    = from_addr
    msg['To']      = to_addr
    msg['X-Mailer']= f'PostmortemCLI {_VERSION}'
    try:
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            smtp.sendmail(from_addr, [to_addr], msg.as_string())
        logger.info(f'Report sent → {to_addr} ({host}:{port})')
        return True
    except Exception as e:
        logger.warning(f'Report SMTP send failed → {e}')
        return False


def report(parsed: dict, result: dict, send_to: str = '') -> str:
    text = generate_report(parsed, result)
    print(text)
    if send_to:
        ok = send_report(send_to, text)
        if ok:
            print(f'  Report sent  → {send_to}\n')
        else:
            print(f'  SMTP delivery failed — saved to file only\n')
    return text