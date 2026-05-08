# src/smtp_reciever.py
# SMTP handler – receives forwarded emails, passes raw bytes + parsed dict to analyzer.
# Not an entrypoint – started by main.py via start_listener()

import asyncio
from email import message_from_bytes
from aiosmtpd.controller import Controller
from src.parser import parse_email
from src.analyzer import analyze
from src.logger import get_logger

logger = get_logger(__name__)

_VERDICT_SYMBOL = {
    'MOST LIKELY SAFE':                    '✓',
    'MOST LIKELY UNSAFE':                   '✗',
    'FURTHER ANALYSIS REQUIRED': '?',
}


class PostMortemHandler:
    async def handle_DATA(self, server, session, envelope):
        raw_bytes = envelope.content
        message   = message_from_bytes(raw_bytes)

        logger.info(f"Email received – From: {message['From']}, Subject: {message['Subject']}")

        parsed = parse_email(message)
        result = analyze(parsed, raw_bytes=raw_bytes)

        _print_result(parsed, result)
        return '250 OK'


def _print_result(parsed: dict, result: dict):
    verdict = result['verdict']
    symbol  = _VERDICT_SYMBOL.get(verdict, '?')
    auth    = result['auth_findings']
    rep     = result['rep_findings']
    urls    = result['url_findings']
    atts    = result['att_findings']

    print(f"\n{'='*56}")
    print(f"  EMAIL RECEIVED VIA SMTP")
    print(f"{'='*56}")
    print(f"  From:         {parsed['headers']['from']}")
    print(f"  Subject:      {parsed['headers']['subject']}")
    print(f"  Domain:       {result['domain']}")
    print(f"  Sender IP:    {result['sender_ip'] or 'unknown'}")
    print(f"  Hops:         {result['header_findings']['received_hops']}")
    print(f"  URLs:         {len(parsed['urls'])} ({urls['checked']} checked)")
    print(f"  Attachments:  {atts['count']}")

    print(f"\n  Authentication:")
    print(f"    SPF:    {auth['spf']['result']}")
    print(f"    DMARC:  {auth['dmarc']['result']} (policy={auth['dmarc']['policy']})")

    dkim = auth['dkim']
    dkim_status = dkim['result']
    if dkim['signature_present']:
        dkim_status += f" | sig={'valid' if dkim['signature_valid'] else 'INVALID' if dkim['signature_valid'] is False else 'unverified'}"
    print(f"    DKIM:   {dkim_status}")

    print(f"    Spamhaus ZEN: {'LISTED' if rep['spamhaus_zen'] else 'clean'}")
    if urls['urlhaus_hits'] or urls['dbl_hits']:
        print(f"    URLhaus hits: {urls['urlhaus_hits']} | DBL hits: {urls['dbl_hits']}")
    if atts['malwarebazaar_hits']:
        print(f"    MalwareBazaar hits: {atts['malwarebazaar_hits']}")

    if result['all_flags']:
        print(f"\n  Flags ({len(result['all_flags'])}):")
        for flag in result['all_flags']:
            print(f"    ⚠  {flag}")

    print(f"\n  VERDICT: [{symbol}] {verdict}")
    print(f"{'='*56}\n")


def start_listener(host: str = '0.0.0.0', port: int = 1025):
    async def _run():
        handler    = PostMortemHandler()
        controller = Controller(handler, hostname=host, port=port)
        controller.start()
        logger.info(f'SMTP listener started on {host}:{port}')
        print(f'[*] SMTP listener running on {host}:{port}')
        print(f'[*] Forward suspicious emails to: scan@localhost\n')
        try:
            await asyncio.sleep(float('inf'))
        except KeyboardInterrupt:
            pass
        finally:
            controller.stop()
            logger.info('SMTP listener stopped')

    asyncio.run(_run())