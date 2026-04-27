# The actual entrypoint for the entire tool

import sys
import os
from email import message_from_bytes
from src.parser import parse_email
# from src.reporter import generate_report
# from src.analyzer import analyze


# Help functions
def load_eml(filepath: str):
    """Läser en .eml-fil från disk och returnerar ett mail-objekt."""

    if not os.path.isfile(filepath):
        print(f"[FEL] Filen hittades inte: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        return message_from_bytes(f.read())


def print_summary(parsed: dict, filepath: str):
    """Skriver ut en strukturerad sammanfattning av det parsade mailet."""

    h = parsed["headers"]

    print(f"\n{'='*50}")
    print(f"  FIL:        {os.path.basename(filepath)}")
    print(f"{'='*50}")
    print(f"  Från:       {h['from']}")
    print(f"  Till:       {h['to']}")
    print(f"  Ämne:       {h['subject']}")
    print(f"  Reply-To:   {h['reply_to']}")
    print(f"  Datum:      {h['date']}")

    if parsed["urls"]:
        print(f"\n  URLs ({len(parsed['urls'])}):")
        for url in parsed["urls"]:
            print(f"    → {url}")

    if parsed["attachments"]:
        print(f"\n  Bilagor ({len(parsed['attachments'])}):")
        for att in parsed["attachments"]:
            print(f"    → {att['filename']}  ({att['content_type']}, {att['size']} bytes)")

    print(f"{'='*50}\n")

#Subcommands
def cmd_scan(files: list):
    """Tar emot en lista med filvägar och kör analys på varje fil."""

    if not files:
        print("[ERROR] Ange minst en .eml-fil att scanna.")
        print("Exempel: python main.py scan tests/samples/phishing_email.eml")
        sys.exit(1)

    for filepath in files:
        print(f"[*] Scanning: {filepath}")

        message = load_eml(filepath)
        parsed  = parse_email(message)

        print_summary(parsed, filepath)

        # Analyzer and reporter here
        # result = analyze(parsed)
        # generate_report(result)


# CLI configuration
COMMANDS = {
    "scan": cmd_scan,
}

USAGE = """
PostmortemCLI – E-mail security anti-malware analyzer

Usage:
  python main.py scan <file.eml> [more files...]

Commands:
  scan    Analyzea one or more emails
"""


def main():
    args = sys.argv[1:]

    if not args:
        print(USAGE)
        sys.exit(0)

    subcommand  = args[0]
    subcommand_args = args[1:]

    if subcommand not in COMMANDS:
        print(f"[ERROR] Unknown command: '{subcommand}'")
        print(USAGE)
        sys.exit(1)

    COMMANDS[subcommand](subcommand_args)


if __name__ == "__main__":
    main()