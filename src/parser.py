# src/parser.py
# Parses a Python mail object into a structured dict.
# Input:  Python email.message.Message object
# Output: { headers, body, attachments, urls }

import re
from email.header import decode_header
from src.logger import get_logger

logger = get_logger(__name__)

# Matches plain text URLs: https://example.com/path?q=1
_URL_PLAIN = re.compile(r'https?://[^\s<>\"\'\]]+')

# Matches href/src attributes in HTML: href="https://..."
_URL_HREF  = re.compile(r'(?:href|src)=["\']?(https?://[^"\'>\s]+)', re.IGNORECASE)


def decode_subject(raw_subject):
    if not raw_subject:
        return ''
    decoded, encoding = decode_header(raw_subject)[0]
    if isinstance(decoded, bytes):
        try:
            return decoded.decode(encoding or 'utf-8', errors='replace')
        except (LookupError, TypeError):
            return decoded.decode('utf-8', errors='replace')
    return decoded


def extract_urls(text):
    """
    Extracts all URLs from text or HTML.
    Handles both plain text URLs and HTML href/src attributes.
    Strips trailing punctuation that is likely not part of the URL.
    """
    if not text:
        return []

    plain = _URL_PLAIN.findall(text)
    hrefs = _URL_HREF.findall(text)

    # Strip common trailing punctuation that regex over-captures
    def clean(url):
        return re.sub(r'[.,;:!\?\)\]>]+$', '', url)

    all_urls = [clean(u) for u in plain + hrefs]
    # Deduplicate preserving order
    seen = set()
    result = []
    for u in all_urls:
        if u not in seen and len(u) > 10:
            seen.add(u)
            result.append(u)
    return result


def parse_email(message):
    logger.debug('Starting email parse')

    headers = {
        'from':                   message.get('From', ''),
        'to':                     message.get('To', ''),
        'subject':                decode_subject(message.get('Subject', '')),
        'reply_to':               message.get('Reply-To', ''),
        'return_path':            message.get('Return-Path', ''),
        'message_id':             message.get('Message-ID', ''),
        'date':                   message.get('Date', ''),
        'x_mailer':               message.get('X-Mailer', ''),
        'authentication_results': message.get('Authentication-Results', ''),
        'received':               message.get_all('Received', []),
    }

    logger.debug(f"Headers extracted – From: {headers['from']}, Subject: {headers['subject']}")

    body_text   = ''
    body_html   = ''
    attachments = []
    urls        = []

    for part in message.walk():
        content_type = part.get_content_type()
        disposition  = part.get_content_disposition()

        if disposition == 'attachment':
            payload  = part.get_payload(decode=True) or b''
            filename = part.get_filename() or 'unknown_file'
            attachments.append({
                'filename':     filename,
                'content_type': content_type,
                'data':         payload,
                'size':         len(payload),
            })
            logger.debug(f'Attachment: {filename} ({content_type}, {len(payload)} bytes)')

        elif content_type == 'text/plain' and disposition != 'attachment':
            payload   = part.get_payload(decode=True) or b''
            body_text = payload.decode('utf-8', errors='replace')
            urls     += extract_urls(body_text)

        elif content_type == 'text/html' and disposition != 'attachment':
            payload   = part.get_payload(decode=True) or b''
            body_html = payload.decode('utf-8', errors='replace')
            urls     += extract_urls(body_html)

    # Final dedup across both text and html parts
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    logger.info(f'Parse complete – {len(attachments)} attachments, {len(deduped)} URLs')

    return {
        'headers':     headers,
        'body':        {'text': body_text, 'html': body_html},
        'attachments': attachments,
        'urls':        deduped,
    }