"""
SMTP configuration checker with enhanced security features.
"""
import logging
import asyncio
import aiosmtplib
from typing import Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class SMTPChecker:
    """Professional SMTP configuration validator"""

    def __init__(self):
        """Initialize SMTP checker"""
        self.smtp = None

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.smtp:
            try:
                await self.smtp.quit()
            except Exception as e:
                logger.error(f"Error closing SMTP connection: {e}")
            finally:
                self.smtp = None

    async def check_smtp(self, host: str, port: int, username: str, password: str) -> Dict[str, Any]:
        """Check SMTP configuration with comprehensive validation"""
        try:
            # Initialize SMTP client with timeout
            self.smtp = aiosmtplib.SMTP(hostname=host, port=port, use_tls=False, timeout=30)

            # Connect and get server info
            await self.smtp.connect()

            # Try STARTTLS if available
            try:
                await self.smtp.starttls()
            except Exception:
                pass

            # Attempt login
            await self.smtp.login(username, password)

            # Verify connection is working
            server_info = await self.smtp.ehlo()

            # Clean disconnect (handled by __aexit__)
            # await self.smtp.quit()

            return {
                'working': True,
                'host': host,
                'port': port,
                'features': self._parse_smtp_features(server_info[1]),
                'encryption': 'TLS' if port in [465, 587] else 'None',
                'auth_type': self._determine_auth_type(server_info[1]),
                'security_level': self._assess_security_level(port, server_info[1])
            }

        except aiosmtplib.SMTPAuthenticationError:
            return {
                'working': False,
                'error': 'Authentication failed. Please check credentials.'
            }
        except asyncio.TimeoutError:
            return {
                'working': False,
                'error': 'Connection timed out. Server may be down or blocked.'
            }
        except Exception as e:
            logger.error(f"SMTP check error: {str(e)}")
            return {
                'working': False,
                'error': f'Connection failed: {str(e)}'
            }

    def _parse_smtp_features(self, features: bytes) -> Dict[str, bool]:
        """Parse SMTP server features"""
        feature_list = features.decode().split('\n')
        return {
            'starttls': any('STARTTLS' in f for f in feature_list),
            'auth': any('AUTH' in f for f in feature_list),
            'pipelining': any('PIPELINING' in f for f in feature_list),
            'size': any('SIZE' in f for f in feature_list),
            'utf8': any('SMTPUTF8' in f for f in feature_list),
            'verify': any('VRFY' in f for f in feature_list)
        }

    def _determine_auth_type(self, features: bytes) -> str:
        """Determine supported authentication methods"""
        feature_list = features.decode().split('\n')
        auth_line = next((f for f in feature_list if 'AUTH' in f), '')
        if not auth_line:
            return 'Unknown'

        auth_methods = []
        if 'PLAIN' in auth_line:
            auth_methods.append('PLAIN')
        if 'LOGIN' in auth_line:
            auth_methods.append('LOGIN')
        if 'CRAM-MD5' in auth_line:
            auth_methods.append('CRAM-MD5')
        if 'XOAUTH2' in auth_line:
            auth_methods.append('XOAUTH2')

        return ', '.join(auth_methods) if auth_methods else 'Unknown'

    def _assess_security_level(self, port: int, features: bytes) -> str:
        """Assess the security level of the SMTP configuration"""
        security_score = 0
        feature_list = features.decode().split('\n')

        # Check for secure port
        if port in [465, 587]:
            security_score += 2

        # Check for STARTTLS
        if any('STARTTLS' in f for f in feature_list):
            security_score += 2

        # Check for strong auth methods
        auth_line = next((f for f in feature_list if 'AUTH' in f), '')
        if 'CRAM-MD5' in auth_line:
            security_score += 2
        elif 'XOAUTH2' in auth_line:
            security_score += 2

        # Return security assessment
        if security_score >= 6:
            return 'High'
        elif security_score >= 3:
            return 'Medium'
        return 'Low'

    def format_check_result(self, result: Dict[str, Any]) -> str:
        """Format checker results for display"""
        if result['working']:
            features = result['features']
            return f"""
🔍 *SMTP Configuration Check*

*Status:* ✅ Working
*Security Level:* {result['security_level']}

*Server Details:*
├ Host: `{result['host']}`
├ Port: {result['port']}
├ Encryption: {result['encryption']}
└ Auth Type: {result['auth_type']}

*Features:*
├ STARTTLS: {'✅' if features['starttls'] else '❌'}
├ AUTH: {'✅' if features['auth'] else '❌'}
├ PIPELINING: {'✅' if features['pipelining'] else '❌'}
├ SIZE: {'✅' if features['size'] else '❌'}
├ UTF8: {'✅' if features['utf8'] else '❌'}
└ VERIFY: {'✅' if features['verify'] else '❌'}

*Security Recommendations:*
{'• Enable STARTTLS for enhanced security' if not features['starttls'] else '• STARTTLS is properly configured'}
{'• Use a secure port (465/587)' if result['port'] not in [465, 587] else '• Using secure port configuration'}
"""
        else:
            return f"""
❌ *SMTP Configuration Failed*

*Error Details:*
{result['error']}

*Recommendations:*
• Verify server hostname and port
• Check credentials
• Ensure server is accessible
• Verify firewall settings
"""