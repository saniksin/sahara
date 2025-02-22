import re
import pytz
import datetime
import imaplib
import email

import asyncio
from email.utils import parsedate_to_datetime
from data.config import logger


class EmailClient:
    def __init__(self, acc_info, mail, password, imap_url='imap.firstmail.ltd'):
        self.address = acc_info
        self.mail = mail
        self.password = password
        self.imap_url = imap_url

    def get_code_sync(self):
        try:
            imap = imaplib.IMAP4_SSL(self.imap_url)
            imap.login(self.mail, self.password)
            imap.select('INBOX')

            status, messages = imap.search(None, 'FROM "notify@email.galxe.com"')
            messages = messages[0].split()
            messages = messages[-1:]

            code = 0

            for msg_num in messages:
                msg_num_str = msg_num.decode('utf-8')  # Конвертируем номер сообщения в строку
                _, msg_data = imap.fetch(msg_num_str, "(RFC822)")
                msg = email.message_from_bytes(msg_data[0][1])
                date_str = msg.get("Date")
                if date_str:
                    email_date = parsedate_to_datetime(date_str)
                    email_date = email_date.astimezone(pytz.utc)
                    current_date = datetime.datetime.now(pytz.utc)
                    diff = (current_date - email_date).total_seconds()
                    if diff < 1200:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/html":
                                    body = part.get_payload(decode=True).decode()
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode()
                        code_pattern = re.compile(r'(\d{6})<\/p>')
                        match = code_pattern.search(body)
                        if match:
                            code = match.group(1)
                            break
            imap.logout()
            return str(code)
        except Exception as e:
            logger.error(f'{self.acc_info} | Ошибка при получении кода: {e}')
            return False

    async def get_code(self) -> str:
        loop = asyncio.get_running_loop()
        for _ in range(3):
            try:
                code = await loop.run_in_executor(None, self.get_code_sync)
                if code and code != "0":
                    return code
            except Exception as e:
                logger.error(f'{self.acc_info} | Ошибка при логине: {e}')
                await asyncio.sleep(5)
        return False