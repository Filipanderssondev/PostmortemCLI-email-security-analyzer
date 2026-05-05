# src/smtp_reciever.py
# SMTP handler – receives forwarded emails and passes them to the parser
# Not an entrypoint – started by main.py via start_listener()

import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

from src.parser import parse_email
from src.logger import get_logger

logger = get_logger(__name__)


class PostMortemHandler(AsyncMessage):
    """
    Handles incoming SMTP messages.
    aiosmtpd calls handle_message() automatically when an email arrives.
    """

    async def handle_message(self, message):
        logger.info(f"Email received – From: {message['From']}, Subject: {message['Subject']}")

        parsed = parse_email(message)

        logger.info(f"SMTP parse complete – URLs: {len(parsed['urls'])}, Attachments: {len(parsed['attachments'])}")

        print("\n=== EMAIL RECEIVED VIA SMTP ===")
        print(f"  From:         {message['From']}")
        print(f"  To:           {message['To']}")
        print(f"  Subject:      {message['Subject']}")
        print(f"  URLs found:   {len(parsed['urls'])}")
        print(f"  Attachments:  {len(parsed['attachments'])}")
        print("================================\n")

        # TODO: wire into analyzer and reporter when ready
        # result = analyze(parsed)
        # generate_report(result)


def start_listener(host: str = "0.0.0.0", port: int = 1025):
    """
    Starts the SMTP server and blocks until stopped.
    Called directly for listen mode, threaded for start mode.
    """

    async def _run():
        handler    = PostMortemHandler()
        controller = Controller(handler, hostname=host, port=port)

        controller.start()
        logger.info(f"SMTP listener started on {host}:{port}")
        print(f"[*] SMTP listener running on {host}:{port}")
        print(f"[*] Forward suspicious emails to: scan@localhost\n")

        try:
            await asyncio.sleep(float("inf"))
        except KeyboardInterrupt:
            pass
        finally:
            controller.stop()
            logger.info("SMTP listener stopped")

    asyncio.run(_run())