# tests/test_receiver.py

import asyncio
import smtplib
from email.mime.text import MIMEText

def send_test_email():
    msg = MIMEText('Hej från Post-Mortem!')
    msg['Subject'] = 'Testmail'
    msg['From'] = 'filip@test.com'
    msg['To'] = 'scan@localhost'

    with smtplib.SMTP('localhost', 1025) as s:
        s.sendmail('filip@test.com', ['scan@localhost'], msg.as_string())
        print('✅ Mail skickat!')

if __name__ == "__main__":
    send_test_email()