# main.py
# Core CLI logic – runs inside the container only
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
from src.smtp_reciever import start_listener
# from src.analyzer import analyze          # Uncomment when ready
# from src.reporter import generate_report  # Uncomment when ready

logger = get_logger(__name__)


#  File loading
def load_eml(filepath: str):
    with open(filepath, "rb") as f:
        return message_from_bytes(f.read())


def load_msg(filepath: str):
    try:
        import extract_msg
    except ImportError:
        logger.error(".msg support requires: pip install extract-msg")
        return None

    msg = extract_msg.openMsg(filepath)
    return message_from_bytes(msg.exportBytes())


def load_email_file(filepath: str):
    """Validates and loads a .eml or .msg file. Returns a Python mail object."""

    if not os.path.isfile(filepath):
        logger.error(f"File not found: {filepath}")
        return None

    ext = os.path.splitext(filepath)[1].lower()
    logger.debug(f"Loading file: {filepath} (format: {ext})")

    if ext == ".eml":
        return load_eml(filepath)
    elif ext == ".msg":
        return load_msg(filepath)
    else:
        logger.error(f"Unsupported format: '{ext}' – supported: .eml, .msg")
        return None


#  Container verification
def verify_container_environment():
    """Verifies that the tool is running inside the expected container environment."""

    checks = {
        "POSTMORTEM_CONTAINER env var": os.environ.get("POSTMORTEM_CONTAINER") == "1",
        "Running as container process":  os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv"),
        "Working directory /app":        os.getcwd() == "/app",
        "Data mount /data exists":       os.path.exists("/data"),
    }

    all_passed = all(checks.values())

    print("\n  Container environment checks:")
    for check, passed in checks.items():
        status = "✓" if passed else "✗"
        print(f"    [{status}] {check}")

    if not all_passed:
        print("\n  [WARNING] Some checks failed – tool may not behave as expected.\n")
    else:
        print("\n  All checks passed.\n")


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
        logger.warning("scan called with no files")
        print("[ERROR] Provide at least one file.")
        print("Usage: postmortemcli scan <file.eml> [files...]")
        return

    for filepath in files:
        logger.info(f"Scanning: {filepath}")
        message = load_email_file(filepath)

        if message is None:
            logger.warning(f"Skipping {filepath} – could not load")
            continue

        parsed = parse_email(message)
        logger.info(f"Parsed – URLs: {len(parsed['urls'])}, Attachments: {len(parsed['attachments'])}")
        print_summary(parsed, filepath)

        # Uncomment when ready:
        # result = analyze(parsed)
        # generate_report(result)


def cmd_listen(args: list):
    """Start SMTP listener on port 1025 – blocks until Ctrl+C."""
    start_listener()


def cmd_send(files: list):
    """Sends .eml or .msg files to the SMTP listener on localhost:1025."""

    import smtplib
    from email import message_from_bytes

    if not files:
        print("[ERROR] Provide at least one file.")
        print("Usage: postmortemcli send <file.eml> [files...]")
        return

    for filepath in files:
        try:
            with open(filepath, "rb") as f:
                message = message_from_bytes(f.read())

            with smtplib.SMTP("localhost", 1025) as smtp:
                smtp.send_message(message)

            print(f"[*] Sent: {filepath}")
            logger.info(f"Sent {filepath} to SMTP listener")

        except FileNotFoundError:
            print(f"[ERROR] File not found: {filepath}")

        except ConnectionRefusedError:
            print("[ERROR] Nothing listening on port 1025.")
            print("        Run 'postmortemcli start' first.")


def start_smtp_background():
    """Starts SMTP listener in a background thread."""
    thread = threading.Thread(target=start_listener, daemon=True)
    # daemon=True = thread dies automatically when main program exits
    thread.start()
    return thread


def cmd_start(args: list):
    """Interactive mode – starts SMTP in background, opens interactive prompt."""

    start_smtp_background()

    time.sleep(0.3)
    # Brief pause so SMTP startup message prints before the banner

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
                     ╚═════╝╚══════╝╚═╝

                P O S T M O R T E M C L I v.0.2.1-alpha
                       by Filip Andersson, 2026
                  Email Security Analysis Tool for SMHI
    """)

    print("  SMTP listener running on port 1025")
    print("  Forward suspicious emails to: scan@localhost")
    print("  Type 'help' for available commands. Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input("postmortemcli > ").strip()

            if not user_input:
                continue

            parts     = user_input.split()
            command   = parts[0]
            arguments = parts[1:]

            if command == "exit":
                print("\n  Shutting down. Container will self-destruct.\n")
                sys.exit(0)

            elif command == "help":
                print("""
  Commands:
    scan <file> [files...]   Analyze one or more email files (.eml or .msg)
    send <file> [files...]   Send files to SMTP listener
    listen                   Restart SMTP listener
    help                     Show this message
    exit                     Quit and destroy container
                """)

            elif command in COMMANDS and command != "start":
                COMMANDS[command](arguments)

            else:
                print(f"  [ERROR] Unknown command: '{command}' – type 'help' for options")

        except KeyboardInterrupt:
            print("\n\n  Shutting down. Container will self-destruct.\n")
            sys.exit(0)


#  CLI handler
COMMANDS = {
    "start":  cmd_start,
    "scan":   cmd_scan,
    "listen": cmd_listen,
    "send":   cmd_send,
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
  postmortemcli scan /data/suspicious.eml
  postmortemcli scan /data/a.eml /data/b.msg
  postmortemcli send tests/samples/phishing_email.eml
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