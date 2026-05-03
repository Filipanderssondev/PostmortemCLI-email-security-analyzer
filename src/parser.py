# src/parser.py
# Parses a Python mail object into a structured dict.
# Used by both scan mode (files) and listen mode (SMTP).
# Input:  Python email.message.Message object
# Output: { headers, body, attachments, urls }

import re
from email.header import decode_header


def decode_subject(raw_subject):
    """Decodes encoded email subjects into readable strings.
    Example: '=?utf-8?b?SGVsbG8=?=' → 'Hello'
    """
    if not raw_subject:
        return ""

    decoded, encoding = decode_header(raw_subject)[0]

    if isinstance(decoded, bytes):
        return decoded.decode(encoding or "utf-8", errors="replace")
    return decoded


def extract_urls(text):
    """Finds all URLs in a block of text using regex."""
    if not text:
        return []
    return re.findall(r'https?://[^\s<>\"]+', text)


def parse_email(message):
    """Main parsing function. Takes a mail object, returns structured dict."""

    headers = {
        "from":       message.get("From", ""),
        "to":         message.get("To", ""),
        "subject":    decode_subject(message.get("Subject", "")),
        "reply_to":   message.get("Reply-To", ""),
        "message_id": message.get("Message-ID", ""),
        "received":   message.get_all("Received", []),
        "date":       message.get("Date", ""),
    }

    body_text   = ""
    body_html   = ""
    attachments = []
    urls        = []

    for part in message.walk():
        content_type = part.get_content_type()
        disposition  = part.get_content_disposition()

        if disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename":     part.get_filename() or "unknown_file",
                "content_type": content_type,
                "data":         payload,
                "size":         len(payload)
            })

        elif content_type == "text/plain" and disposition != "attachment":
            payload   = part.get_payload(decode=True) or b""
            body_text = payload.decode("utf-8", errors="replace")
            urls     += extract_urls(body_text)

        elif content_type == "text/html" and disposition != "attachment":
            payload   = part.get_payload(decode=True) or b""
            body_html = payload.decode("utf-8", errors="replace")
            urls     += extract_urls(body_html)

    urls = list(set(urls))

    return {
        "headers":     headers,
        "body": {
            "text": body_text,
            "html": body_html,
        },
        "attachments": attachments,
        "urls":        urls,
    }