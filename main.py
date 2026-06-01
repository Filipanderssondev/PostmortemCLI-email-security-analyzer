# main.py
# Core CLI logic – runs inside the container only.
# Usage:
#   postmortemcli start                      Interactive mode + SMTP listener
#   postmortemcli scan <file.eml> [files...] Scan files directly
#   postmortemcli listen                     SMTP listener only

import sys
import os
import time
import threading
from email import message_from_bytes

from src.logger import get_logger
from src.parser import parse_email
from src.analyzer import analyze
from src.smtp_reciever import start_listener
from src.reporter import report, generate_report
from datetime import datetime
from src.sender import save

logger = get_logger(__name__)

try:
    from importlib.metadata import version as _pkg_version
    _VERSION = _pkg_version('postmortemcli')
except Exception:
    _VERSION = '0.3.9-beta'

_VERDICT_SYMBOL = {
    'MOST LIKELY SAFE':                    '✓',
    'MOST LIKELY UNSAFE':                   '✗',
    'FURTHER ANALYSIS REQUIRED': '?',
}


# ── File loading ──────────────────────────────────────────────────────────────

def load_eml(filepath: str) -> tuple:
    with open(filepath, 'rb') as f:
        raw_bytes = f.read()
    return message_from_bytes(raw_bytes), raw_bytes


def load_msg(filepath: str) -> tuple:
    try:
        import extract_msg
    except ImportError:
        logger.error('.msg support requires: pip install extract-msg')
        return None, b''
    msg       = extract_msg.openMsg(filepath)
    raw_bytes = msg.exportBytes()
    return message_from_bytes(raw_bytes), raw_bytes


def load_email_file(filepath: str) -> tuple:
    if not os.path.isfile(filepath):
        logger.error(f'File not found: {filepath}')
        return None, b''

    ext = os.path.splitext(filepath)[1].lower()
    logger.debug(f'Loading {filepath} ({ext})')

    if ext == '.eml':
        return load_eml(filepath)
    elif ext == '.msg':
        return load_msg(filepath)
    else:
        logger.error(f'Unsupported format: {ext} – supported: .eml, .msg')
        return None, b''


# ── Container verification ────────────────────────────────────────────────────

def verify_container_environment():
    checks = {
        'POSTMORTEM_CONTAINER env var': os.environ.get('POSTMORTEM_CONTAINER') == '1',
        'Running as container process':  os.path.exists('/run/.containerenv') or os.path.exists('/.dockerenv'),
        'Working directory /app':        os.getcwd() == '/app',
        'Data mount /data exists':       os.path.exists('/data'),
    }

    all_passed = all(checks.values())

    print('\n  Container environment checks:')
    for check, passed in checks.items():
        print(f"    [{'✓' if passed else '✗'}] {check}")

    if not all_passed:
        print('\n  [WARNING] Some checks failed – tool may not behave as expected.\n')
    else:
        print('\n  All checks passed.\n')


# ── Output ────────────────────────────────────────────────────────────────────

def print_result(parsed: dict, filepath: str, result: dict):
    h       = parsed['headers']
    verdict = result['verdict']
    symbol  = _VERDICT_SYMBOL.get(verdict, '?')
    auth    = result['auth_findings']
    rep     = result['rep_findings']
    urls    = result['url_findings']
    atts    = result['att_findings']

    print(f"\n{'='*56}")
    print(f"  FILE: {os.path.basename(filepath)}")
    print(f"{'='*56}")
    print(f"  From:        {h['from']}")
    print(f"  To:          {h['to']}")
    print(f"  Subject:     {h['subject']}")
    print(f"  Reply-To:    {h['reply_to']}")
    print(f"  Return-Path: {h['return_path']}")
    print(f"  Date:        {h['date']}")
    print(f"  Message-ID:  {h['message_id']}")
    print(f"  Domain:      {result['domain']}")
    print(f"  Sender IP:   {result['sender_ip'] or 'unknown'}")
    print(f"  Hops:        {result['header_findings']['received_hops']}")

    print(f"\n  Received chain:")
    for hop in h['received']:
        print(f"    → {hop[:80]}{'...' if len(hop) > 80 else ''}")

    if parsed['urls']:
        print(f"\n  URLs ({len(parsed['urls'])}, {urls['checked']} checked):")
        for url in parsed['urls']:
            hit = next((r for r in urls['results'] if r['url'] == url), {})
            tag = ' ⚠ URLhaus' if hit.get('urlhaus') else (' ⚠ DBL' if hit.get('spamhaus_dbl') else '')
            print(f"    🔗 {url}{tag}")
    else:
        print('\n  URLs: none')

    if atts['count']:
        print(f"\n  Attachments ({atts['count']}):")
        for a in atts['results']:
            tags = []
            if a['malwarebazaar']:  tags.append('⚠ MalwareBazaar')
            if a['dangerous']:      tags.append('⚠ dangerous ext')
            if a['mime_mismatch']:  tags.append('⚠ MIME mismatch')
            tag_str = '  ' + '  '.join(tags) if tags else ''
            print(f"    📎 {a['filename']} ({a['declared_mime']}, {a['size']} bytes){tag_str}")
            print(f"       sha256: {a['sha256']}")
    else:
        print('  Attachments: none')

    print(f"\n  Authentication:")
    print(f"    SPF:   {auth['spf']['result']}")
    print(f"    DMARC: {auth['dmarc']['result']} (policy={auth['dmarc']['policy']})")

    dkim = auth['dkim']
    dkim_line = dkim['result']
    if dkim['signature_present']:
        sig = 'valid' if dkim['signature_valid'] else ('INVALID' if dkim['signature_valid'] is False else 'unverified')
        dkim_line += f" | sig={sig}"
    print(f"    DKIM:  {dkim_line}")
    print(f"    Spamhaus ZEN: {'LISTED' if rep['spamhaus_zen'] else 'clean'}")

    if result['all_flags']:
        print(f"\n  Flags ({len(result['all_flags'])}):")
        for flag in result['all_flags']:
            print(f"    ⚠  {flag}")

    print(f"\n  VERDICT: [{symbol}] {verdict}")
    print(f"{'='*56}\n")


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_scan(files: list):
    if not files:
        print('[ERROR] Provide at least one file.')
        print('Usage: postmortemcli scan <file.eml> [files...]')
        return

    for filepath in files:
        logger.info(f'Scanning: {filepath}')
        message, raw_bytes = load_email_file(filepath)

        if message is None:
            logger.warning(f'Skipping {filepath} – could not load')
            continue

        parsed = parse_email(message)
        logger.info(f"Parsed – URLs: {len(parsed['urls'])}, Attachments: {len(parsed['attachments'])}")

        result = analyze(parsed, raw_bytes=raw_bytes)
        print_result(parsed, filepath, result)
        report_text = generate_report(parsed, result)
        print(report_text)
        save(report_text, f'PMRT-{datetime.now().strftime("%Y%m%d-%H%M%S")}')


def cmd_listen(args: list):
    start_listener()


def cmd_send(files: list):
    import smtplib

    if not files:
        print('[ERROR] Provide at least one file.')
        print('Usage: postmortemcli send <file.eml> [files...]')
        return

    for filepath in files:
        try:
            with open(filepath, 'rb') as f:
                message = message_from_bytes(f.read())

            with smtplib.SMTP('localhost', 1025) as smtp:
                smtp.send_message(message)

            print(f'[*] Sent: {filepath}')
            logger.info(f'Sent {filepath} to SMTP listener')

        except FileNotFoundError:
            print(f'[ERROR] File not found: {filepath}')
        except ConnectionRefusedError:
            print('[ERROR] Nothing listening on port 1025.')
            print("        Run 'postmortemcli start' first.")


def start_smtp_background():
    thread = threading.Thread(target=start_listener, daemon=True)
    thread.start()
    return thread


def cmd_start(args: list):
    start_smtp_background()
    time.sleep(0.3)
    verify_container_environment()

    print("""
██████╗  ██████╗ ███████╗████████╗███╗   ███╗ ██████╗ ██████╗ ████████╗███████╗███╗   ███╗
██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝████╗ ████║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝████╗ ████║
██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║██║   ██║██████╔╝   ██║   █████╗  ██╔████╔██║
██╔═══╝ ██║   ██║╚════██║   ██║   ██║╚██╔╝██║██║   ██║██╔══██╗   ██║   ██╔══╝  ██║╚██╔╝██║
██║     ╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   ███████╗██║ ╚═╝ ██║
╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝

                     ██████╗██╗     ██╗
                    ██╔════╝██║     ██║
                    ██║     ██║     ██║
                    ██║     ██║     ██║
                    ╚██████╗███████╗██║
                     ╚═════╝╚══════╝╚═╝""")
    print(f"          P O S T M O R T E M C L I v{_VERSION}")
    print("""              by Filip Andersson, 2026
                  Email Security Analysis Tool for SMHI""")
    print(f'[*] SMTP endpoint: localhost:1025')
    print(f'[*] Submit emails using: postmortemcli send <file.eml>\n')
    print("  Type 'help' for available commands. Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input('postmortemcli > ').strip()

            if not user_input:
                continue

            parts     = user_input.split()
            command   = parts[0]
            arguments = parts[1:]

            if command == 'exit':
                print('\n  Shutting down. Container will self-destruct.\n')
                sys.exit(0)

            elif command == 'help':
                print("""
  Commands:
    scan <file> [files...]   Analyze one or more email files (.eml or .msg)
    send <file> [files...]   Send files to SMTP listener (.eml or .msg)
    listen                   Restart SMTP listener
    help                     Show this message
    exit                     Quit and destroy container
                """)

            elif command in COMMANDS and command != 'start':
                COMMANDS[command](arguments)

            else:
                print(f"  [ERROR] Unknown command: '{command}' – type 'help' for options")

        except KeyboardInterrupt:
            print('\n\n  Shutting down. Container will self-destruct.\n')
            sys.exit(0)


# ── CLI handler ───────────────────────────────────────────────────────────────

COMMANDS = {
    'start':  cmd_start,
    'listen': cmd_listen,
    'send':   cmd_send,
    'scan':   cmd_scan,
}

USAGE = """
PostmortemCLI – Email security analysis tool, containerized CLI for structured threat detection

Usage:
  postmortemcli start                    Interactive mode + SMTP listener
  postmortemcli listen                   SMTP listener only
  postmortemcli scan <file> [files...]   Scan email files directly
  postmortemcli send <file> [files...]   Send files to SMTP listener

Examples:
  postmortemcli start

  FILE ANALYSIS: ( drag file or paste filepath here )
  postmortemcli scan /data/email.eml /data/email.msg
  postmortemcli send /path/to/email.eml /path/to/email.msg ( drag file or paste filepath here ) 
"""


def main():
    args = sys.argv[1:]

    if not args:
        print(USAGE)
        sys.exit(0)

    subcommand      = args[0]
    subcommand_args = args[1:]

    if subcommand not in COMMANDS:
        print(f"[ERROR] Unknown command: '{subcommand}'")
        print(USAGE)
        sys.exit(1)

    COMMANDS[subcommand](subcommand_args)


if __name__ == '__main__':
    main()