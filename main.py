# The actual entrypoint for the entire tool
# Entry point for the PostmortemCLI tool
# Usage: postmortem scan <file.eml> [additional files...]

import sys
import os
from email import message_from_bytes

from src.parser import parse_email
# from src.analyzer import analyze          # Uncomment when analyzer.py is ready
# from src.reporter import generate_report  # Uncomment when reporter.py is ready



#  File loading
def load_eml(filepath: str):
    with open(filepath, "rb") as f:
        return message_from_bytes(f.read())
        # message_from_bytes() converts raw bytes into a Python mail object
        # Same type that aiosmtpd delivers – parser works without changes

# Loads a .msg
def load_msg(filepath: str):
    """Reads a .msg file (Outlook format) and returns a mail object."""

    try:
        import extract_msg
        # extract_msg = third-party library for reading Outlook's .msg format
        # Only imported here – no error if not installed unless .msg is actually used
    except ImportError:
        print("[ERROR] .msg support requires: pip install extract-msg")
        sys.exit(1)

    msg = extract_msg.openMsg(filepath)
    # Opens the .msg file and parses it into an extract_msg object

    return message_from_bytes(msg.exportBytes())
    # exportBytes() converts .msg to standard RFC822 bytes
    # message_from_bytes() wraps it – parser receives the exact same format as .eml


def load_email_file(filepath: str):
    """
    Loads a .eml or .msg file from disk.
    Validates that the file exists and that the format is supported.
    Returns a Python mail object ready for parsing.
    """

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
        # sys.exit(1) = exit with error code 1 (Unix standard for failure)

    ext = os.path.splitext(filepath)[1].lower()
    # os.path.splitext() splits filename into (name, extension)
    # "suspicious.MSG" → ".msg" after .lower()
    # .lower() ensures .EML and .eml are treated the same

    if ext == ".eml":
        return load_eml(filepath)

    elif ext == ".msg":
        return load_msg(filepath)

    else:
        print(f"[ERROR] Unsupported file format: '{ext}'")
        print("        Supported formats: .eml, .msg")
        sys.exit(1)


#  Output
def print_summary(parsed: dict, filepath: str):
    """
    Prints a structured summary of the parsed email to the terminal.
    Placeholder until analyzer.py and reporter.py are complete.
    """

    h = parsed["headers"]

    print(f"\n{'='*52}")
    print(f"  FILE:        {os.path.basename(filepath)}")
    # os.path.basename() strips the folder path, returns just the filename
    # "tests/samples/phishing.eml" → "phishing.eml"
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
        # [:80] = first 80 characters only – Received headers can be very long

    if parsed["urls"]:
        print(f"\n  URLs found ({len(parsed['urls'])}):")
        for url in parsed["urls"]:
            print(f"    🔗 {url}")
    else:
        print("\n  URLs found: none")

    if parsed["attachments"]:
        print(f"\n  Attachments ({len(parsed['attachments'])}):")
        for att in parsed["attachments"]:
            print(f"    📎 {att['filename']}  ({att['content_type']}, {att['size']} bytes)")
    else:
        print("  Attachments: none")

    print(f"{'='*52}\n")

    # ── Verdict placeholder ──────────────────────────────
    # Will be replaced by analyzer.py output
    print("  VERDICT:     [ pending – analyzer not yet implemented ]")
    print(f"{'='*52}\n")


#  Subcommands
def cmd_scan(files: list):
    """
    Accepts a list of file paths and runs analysis on each one.
    Supports .eml and .msg formats.
    """

    if not files:
        print("[ERROR] Please provide at least one file to scan.")
        print("Usage:  postmortem scan <file.eml> [additional files...]")
        print("Example: postmortem scan suspicious.eml invoice.msg")
        sys.exit(1)

    for filepath in files:
        # Loops through all files provided
        # postmortem scan a.eml b.msg c.eml → three separate analyses

        print(f"[*] Scanning: {filepath}")

        message = load_email_file(filepath)
        # Handles both .eml and .msg, exits cleanly on unsupported formats

        parsed = parse_email(message)
        # Returns a dict: { headers, body, attachments, urls }

        print_summary(parsed, filepath)

        # Activate when analyzer and reporter are ready:
        # result  = analyze(parsed)
        # generate_report(result)


#  CLI handler
COMMANDS = {
    "scan": cmd_scan,
    # New subcommands will be added here as the project grows:
    # "report":  cmd_report,
    # "version": cmd_version,
}
# Dict lookup instead of if/elif –
# adding a new command is always exactly one line, nothing else changes


USAGE = """
PostmortemCLI – Email Security Analysis Tool

Usage:
  postmortem scan <file> [additional files...]

Commands:
  scan    Analyze one or more email files (.eml or .msg)

Examples:
  postmortem scan suspicious.eml
  postmortem scan email1.eml email2.msg invoice.eml
"""


def main():
    args = sys.argv[1:]
    # sys.argv = everything typed in the terminal as a list
    # sys.argv[0] = program name
    # sys.argv[1:] = everything after
    # "postmortem scan a.eml b.msg" → args = ["scan", "a.eml", "b.msg"]

    if not args:
        print(USAGE)
        sys.exit(0)

    subcommand      = args[0]
    subcommand_args = args[1:]
    # "scan"       → cmd_scan
    # "a.eml b.msg" → passed into cmd_scan as the files list

    if subcommand not in COMMANDS:
        print(f"[ERROR] Unknown command: '{subcommand}'")
        print(USAGE)
        sys.exit(1)

    COMMANDS[subcommand](subcommand_args)


if __name__ == "__main__":
    main()