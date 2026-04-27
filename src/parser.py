import re
from email.header import decode_header

def decode_subject(raw_subject):  
    if not raw_subject:
        return ""

    decoded, encoding = decode_header(raw_subject)[0]

    if isinstance(decoded, bytes):
        return decoded.decode(encoding or "utf-8", errors="replace")
    return decoded

# Extract all URLs matching 
def extract_urls(text):
    if not text:
        return []
    return re.findall(r'https?://[^\s<>\"]+', text)


def parse_email(message):

    # --- HEADERS --- Metadata from the mail
    headers = {
        "from":       message.get("From", ""),
        "to":         message.get("To", ""),
        "subject":    decode_subject(message.get("Subject", "")),
        "reply_to":   message.get("Reply-To", ""),
        "message_id": message.get("Message-ID", ""),
        "received":   message.get_all("Received", []),
        "date":       message.get("Date", ""),
    }

    # --- BODY + ATTACHMENTS ---
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
                "filename":     part.get_filename() or "Unknown_file",
                "content_type": content_type,
                "data":         payload,
                "size":         len(payload)
            })

        elif content_type == "text/plain" and disposition != "attachment":
            payload    = part.get_payload(decode=True) or b""
            body_text  = payload.decode("utf-8", errors="replace")
            urls      += extract_urls(body_text)

        elif content_type == "text/html" and disposition != "attachment":
            payload    = part.get_payload(decode=True) or b""
            body_html  = payload.decode("utf-8", errors="replace")
            urls      += extract_urls(body_html)
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