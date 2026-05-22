# src/smtp_reciever.py
# SMTP handler – receives forwarded emails via SMTP on port 1025.
# Queues incoming messages and processes them sequentially.
# Pipeline: smtp_reciever → parser → analyzer → reporter → sender

import asyncio
import queue
import threading
from email import message_from_bytes
from aiosmtpd.controller import Controller
from src.parser import parse_email
from src.analyzer import analyze
from src.reporter import report
from src.logger import get_logger

logger = get_logger(__name__)

# Thread-safe queue for incoming emails
_email_queue = queue.Queue()


def _process_queue():
    """Worker thread — processes emails from queue sequentially."""
    while True:
        try:
            raw_bytes = _email_queue.get()
            if raw_bytes is None:
                break
            message = message_from_bytes(raw_bytes)
            parsed  = parse_email(message)
            result  = analyze(parsed, raw_bytes=raw_bytes)
            report(parsed, result)
            # TODO: sender.send_report() when implemented
        except Exception as e:
            logger.error(f'Error processing email: {e}')
        finally:
            _email_queue.task_done()


class PostMortemHandler:
    async def handle_DATA(self, server, session, envelope):
        try:
            raw_bytes = envelope.content
            message   = message_from_bytes(raw_bytes)
            logger.info(
                f"Email received – From: {message['From']}, "
                f"Subject: {message['Subject']}"
            )
            _email_queue.put(raw_bytes)
        except Exception as e:
            logger.error(f'Failed to queue email: {e}')
            return '451 Internal error'
        return '250 OK'


def start_listener(host: str = '0.0.0.0', port: int = 1025):
    # Start worker thread for processing queue
    worker = threading.Thread(target=_process_queue, daemon=True)
    worker.start()

    async def _run():
        handler    = PostMortemHandler()
        controller = Controller(handler, hostname=host, port=port)
        controller.start()
        logger.info(f'SMTP listener started on {host}:{port}')
        print(f'[*] SMTP listener running on {host}:{port}')
        print(f'[*] SMTP endpoint: localhost:{port}')
        print(f'[*] Submit emails using: postmortemcli send <file.eml>\n')
        try:
            await asyncio.sleep(float('inf'))
        except KeyboardInterrupt:
            pass
        finally:
            controller.stop()
            logger.info('SMTP listener stopped')
    asyncio.run(_run())