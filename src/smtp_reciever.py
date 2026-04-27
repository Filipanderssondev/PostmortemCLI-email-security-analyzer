# This is the local e-mail reciever server, The "mailbox", an SMTP server listening after incoming mail

import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

class PostMortemMessageHandler(AsyncMessage):
    async def handle_message(self, message):
        print("\n")
        print("=== NEW MAIL RECIEVED ===")
        print(f"From:     {message['From']}")
        print(f"To:     {message['To']}")
        print(f"Subject:     {message['Subject']}")
        print("==========================")
        print("\n")

        # Call parser.py here
        # parsed = parse_email(message)
        # result = analyze(parsed)
        # send_report(result)


# The Main function (Obviously, but comment for structure)
async def main():
    handler = PostMortemMessageHandler()        
    controller = Controller(
        handler,
        hostname="0.0.0.0",
        port=1025               
    )

    controller.start()
    print("Post-Mortem SMTP-reciever running on port 1025...")
    print("Send mail to: scan@localhost")
    print("Press Ctrl+C to stop.")

    try:
        await asyncio.sleep(float("inf")) 
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        print("Server stopped.")

if __name__ == "__main__":
    asyncio.run(main()) 
