# main.py
# Entrypoint for PostmortemCLI
# Usage:
#   postmortemcli scan <file.eml> [files...]
#   postmortemcli listen

import sys
import os
from email import message_from_bytes

from src.parser import parse_email
from src.smtp_reciever import start_listener
# from src.analyzer import analyze          # Uncomment when ready
# from src.reporter import generate_report  # Uncomment when ready


#  File loading
def load_eml(filepath: str):
    with open(filepath, "rb") as f:
        return message_from_bytes(f.read())

def load_msg(filepath: str):
    try:
        import extract_msg
    except ImportError:
        print("[ERROR] .msg support requires: pip install extract-msg")
        sys.exit(1)

    msg = extract_msg.openMsg(filepath)
    return message_from_bytes(msg.exportBytes())


def load_email_file(filepath: str):
    """Validates and loads a .eml or .msg file. Returns a Python mail object."""

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".eml":
        return load_eml(filepath)
    elif ext == ".msg":
        return load_msg(filepath)
    else:
        print(f"[ERROR] Unsupported format: '{ext}' – supported: .eml, .msg")
        sys.exit(1)


#  Output
def print_summary(parsed: dict, filepath: str):
    """Prints parsed email summary. Placeholder until analyzer.py is ready."""

    h = parsed["headers"]

    print(f"\n{'='*52}")
    print(f"  FILE:        {os.path.basename(filepath)}")
    print(f"{'='*52}")
    print(f"  From:        {h['from']}")
    print(f"  To:          {h['to']}")
    print(f"  Subject:     {h['subject']}")
    print(f"  Reply-To:    {h['reply_to']}")
    print(f"  Date:        {h['date']}")
    print(f"  Message-ID:  {h['message_id']}")

    print(f"\n  Received chain ({len(h['received'])} hops):")
    for hop in h["received"]:
        print(f"    → {hop[:80]}...")

    if parsed["urls"]:
        print(f"\n  URLs ({len(parsed['urls'])}):")
        for url in parsed["urls"]:
            print(f"    🔗 {url}")
    else:
        print("\n  URLs: none")

    if parsed["attachments"]:
        print(f"\n  Attachments ({len(parsed['attachments'])}):")
        for att in parsed["attachments"]:
            print(f"    📎 {att['filename']} ({att['content_type']}, {att['size']} bytes)")
    else:
        print("  Attachments: none")

    print(f"\n  VERDICT: [ pending – analyzer not yet implemented ]")
    print(f"{'='*52}\n")


#  Subcommands
def cmd_scan(files: list):
    """Scan one or more .eml / .msg files directly from disk."""

    if not files:
        print("[ERROR] Provide at least one file.")
        print("Usage: postmortemcli scan <file.eml> [files...]")
        sys.exit(1)

    for filepath in files:
        print(f"[*] Scanning: {filepath}")
        message = load_email_file(filepath)
        parsed  = parse_email(message)
        print_summary(parsed, filepath)

        # Uncomment when ready:
        # result = analyze(parsed)
        # generate_report(result)


def cmd_listen(args: list):
    """Start SMTP listener on port 1025."""
    start_listener()


#  CLI handler
COMMANDS = {
    "scan":   cmd_scan,
    "listen": cmd_listen,
}

USAGE = """
PostmortemCLI – Email Security Analysis Tool

Usage:
  postmortemcli scan <file> [files...]   Analyze email files directly
  postmortemcli listen                   Start SMTP listener on port 1025

Examples:
  postmortemcli scan suspicious.eml
  postmortemcli scan a.eml b.msg c.eml
  postmortemcli listen
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


if __name__ == "__main__":
    main()