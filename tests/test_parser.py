# tests/test_parser.py

from email import message_from_string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import sys
sys.path.insert(0, "src")

from src/parser.py import parse_email


def build_simple_email():
    # Bygger ett enkelt textmail
    msg = MIMEText("Hej, klicka här: https://evil.ru/malware")
    msg["Subject"] = "Enkelt testmail"
    msg["From"]    = "hacker@suspicious.ru"
    msg["To"]      = "scan@localhost"
    return message_from_string(msg.as_string())


def build_email_with_attachment():
    msg = MIMEMultipart()
    msg["Subject"] = "Mail med bilaga"
    msg["From"]    = "hacker@suspicious.ru"
    msg["To"]      = "scan@localhost"
    msg["Reply-To"]= "annan@evil.ru"

    msg.attach(MIMEText("Öppna bilagan!"))

    attachment = MIMEBase("application", "octet-stream")
    attachment.set_payload(b"fake malware content")
    encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename="invoice.exe")
    msg.attach(attachment)

    return message_from_string(msg.as_string())


def test_simple_email():
    print("TEST 1: Enkelt mail")
    parsed = parse_email(build_simple_email())

    assert parsed["headers"]["from"]    == "hacker@suspicious.ru", "From stämmer inte"
    assert parsed["headers"]["subject"] == "Enkelt testmail",       "Subject stämmer inte"
    assert "https://evil.ru/malware" in parsed["urls"],             "URL hittades inte"
    assert len(parsed["attachments"])   == 0,                       "Ska inte ha bilagor"

    print("  ✅ Headers läses korrekt")
    print("  ✅ URL extraherad")
    print("  ✅ Inga bilagor (korrekt)")


def test_email_with_attachment():
    print("TEST 2: Mail med bilaga")
    parsed = parse_email(build_email_with_attachment())

    assert parsed["headers"]["reply_to"]       == "annan@evil.ru", "Reply-To stämmer inte"
    assert len(parsed["attachments"])          == 1,               "Ska ha 1 bilaga"
    assert parsed["attachments"][0]["filename"]== "invoice.exe",   "Filnamn stämmer inte"
    assert parsed["attachments"][0]["size"]     > 0,               "Filstorlek ska vara > 0"

    print("  ✅ Reply-To läses korrekt")
    print("  ✅ Attachment found")
    print("  ✅ Filnamn korrekt")
    print("  ✅ Filstorlek korrekt")


if __name__ == "__main__":
    print("=== Testing parser.py ===\n")
    test_simple_email()
    print()
    test_email_with_attachment()
    print("\n✅ All tests passed!")