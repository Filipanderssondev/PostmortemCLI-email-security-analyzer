# This is the e-mail reciever, The "mailbox", an SMTP server listening after incoming mail

import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage


class PostMortemHandler(AsyncMessage):
    async def handle_message(self, message):
        print("=== NYTT MAIL MOTTAGET ===")
        print(f"Från:     {message['From']}")
        print(f"Till:     {message['To']}")
        print(f"Ämne:     {message['Subject']}")
        print("==========================")

        # Calling parser.py here later 
        # parsed = parse_email(message)
        # result = analyze(parsed)
        # send_report(result)

async def main():

    handler = PostMortemHandler()        
    controller = Controller(
        handler,
        hostname="0.0.0.0",               
    )

    controller.start()
    print("📬 Post-Mortem SMTP-mottagare körs på port 1025...")
    print("Skicka mail till: scan@localhost")
    print("Tryck Ctrl+C för att stoppa.")

    try:
        await asyncio.sleep(float("inf")) 
    except KeyboardInterrupt:
        pass

    finally:
        controller.stop()
        print("Server stoppad.")

if __name__ == "__main__":
    asyncio.run(main()) 
