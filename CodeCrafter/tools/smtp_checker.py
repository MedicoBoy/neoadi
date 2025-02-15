"""
SMTP checker functionality for the bot.
Adapted from Aron-Tn/SMTP-CRACKER-V2
"""
import smtplib
import dns.resolver
from typing import Dict, Union, List, Any
import asyncio
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor

class SMTPChecker:
    def __init__(self):
        self.timeout = 10
        self.test_email = "test@example.com"

    async def check_smtp(self, host: str, port: int, username: str, password: str) -> Dict[str, Any]:
        """
        Check SMTP credentials
        """
        try:
            # Run SMTP check in thread pool to avoid blocking
            with ThreadPoolExecutor() as executor:
                future = executor.submit(self._check_smtp_sync, host, port, username, password)
                result = await asyncio.get_event_loop().run_in_executor(
                    None, future.result
                )
            return result
        except Exception as e:
            return {
                'valid': False,
                'message': str(e),
                'host': host,
                'port': port
            }

    def _check_smtp_sync(self, host: str, port: int, username: str, password: str) -> Dict[str, Any]:
        """
        Synchronous SMTP check
        """
        try:
            if port == 587:
                smtp = smtplib.SMTP(host, port, timeout=self.timeout)
                smtp.starttls()
            else:
                smtp = smtplib.SMTP_SSL(host, port, timeout=self.timeout)

            smtp.login(username, password)

            # Try sending test email
            msg = MIMEText('SMTP Test')
            msg['Subject'] = 'SMTP Test'
            msg['From'] = username
            msg['To'] = self.test_email

            smtp.sendmail(username, [self.test_email], msg.as_string())
            smtp.quit()

            return {
                'valid': True,
                'message': 'SMTP credentials valid',
                'host': host,
                'port': port
            }
        except smtplib.SMTPAuthenticationError:
            return {
                'valid': False,
                'message': 'Authentication failed',
                'host': host,
                'port': port
            }
        except Exception as e:
            return {
                'valid': False,
                'message': str(e),
                'host': host,
                'port': port
            }

    async def verify_domain(self, domain: str) -> Dict[str, Any]:
        """
        Verify domain MX records
        """
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if mx_records:
                return {
                    'valid': True,
                    'message': f'Found {len(mx_records)} MX records',
                    'records': [str(x.exchange) for x in mx_records]
                }
            return {
                'valid': False,
                'message': 'No MX records found'
            }
        except Exception as e:
            return {
                'valid': False,
                'message': str(e)
            }