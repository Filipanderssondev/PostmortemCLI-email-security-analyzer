# src/smtp_receiver.py
# SMTP handler – receives forwarded emails and passes them to the parser.
# Not an entrypoint. main.py starts this via cmd_listen().

import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

from src.parser import parse_email


class PostMortemHandler(AsyncMessage):
    """
    Handles incoming SMTP messages.
    aiosmtpd calls handle_message() automatically each time an email arrives.
    """

    async def handle_message(self, message):
        print("\n=== EMAIL RECEIVED ===")
        print(f"  From:    {message['From']}")
        print(f"  To:      {message['To']}")
        print(f"  Subject: {message['Subject']}")
        print("======================")

        parsed = parse_email(message)

        # TODO: wire into analyzer and reporter when ready
        # result = analyze(parsed)
        # generate_report(result)

        print(f"  URLs found:   {len(parsed['urls'])}")
        print(f"  Attachments:  {len(parsed['attachments'])}")
        print("======================\n")


def start_listener(host: str = "0.0.0.0", port: int = 1025):
    """
    Starts the SMTP server and blocks until Ctrl+C.
    Called by main.py when user runs: postmortemcli listen
    """

    async def _run():
        handler    = PostMortemHandler()
        controller = Controller(handler, hostname=host, port=port)

        controller.start()
        print(f"[*] Listening for emails on {host}:{port}")
        print(f"[*] Forward suspicious emails to: scan@localhost")
        print(f"[*] Press Ctrl+C to stop.\n")

        try:
            await asyncio.sleep(float("inf"))
        except KeyboardInterrupt:
            pass
        finally:
            controller.stop()
            print("\n[*] Listener stopped.")

    asyncio.run(_run())