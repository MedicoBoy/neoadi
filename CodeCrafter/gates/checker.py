"""
Payment gateway checker functionality with enhanced security and OTP bypass.
"""
from typing import Dict, Optional, List, Any, Union, TypedDict, Literal
import aiohttp
import json
import logging
import asyncio
from typing import Dict, Optional, List, Any, Union, TypedDict, Literal
from fake_useragent import UserAgent
from datetime import datetime
from bot.cc_utils import CCValidator
from bot.otp_bypass import OTPBypass
from configs.values import GATES, TEST_CARDS
from configs.tokens import STRIPE_KEY, SQUARE_KEY

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class GateResponse(TypedDict, total=False):
    status: str
    message: str
    gate: str
    requires_3ds: bool
    error_code: Optional[str]

class GateChecker:
    """Payment gateway checker with enhanced security"""

    def __init__(self):
        self.ua = UserAgent()
        self.session: Optional[aiohttp.ClientSession] = None
        self.api_keys = {
            'stripe': STRIPE_KEY,
            'square': SQUARE_KEY
        }
        self.test_cards = TEST_CARDS
        self.validator = CCValidator()
        self.otp_bypass = OTPBypass()
        logger.info("GateChecker initialized with configuration")

    async def __aenter__(self):
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_card(self, card: str, month: str, year: str) -> Dict[str, Any]:
        """Check card against available payment gateways"""
        try:
            # Initial validation
            validation = await self.validator.validate_card(card, month, year, '000')
            if not validation['valid']:
                return {
                    'status': 'invalid',
                    'message': validation.get('error', 'Invalid card'),
                    'details': {
                        'card_type': validation.get('card_type', 'Unknown'),
                        'bin_info': validation.get('bin_info', {}),
                    }
                }

            # Check test cards
            test_card_info = self._check_test_card(card)
            if test_card_info['is_test']:
                return test_card_info

            # Gate checks with OTP bypass
            gate_results = await self._run_gate_checks(card, month, year)

            return {
                'status': 'valid' if gate_results['valid_count'] > 0 else 'invalid',
                'message': self._format_status_message(gate_results),
                'details': {
                    'card_type': validation.get('card_type', 'Unknown'),
                    'bin_info': validation.get('bin_info', {}),
                    'security': validation.get('security_checks', {}),
                    'risk_level': self._calculate_risk_level(validation),
                    'gates': [
                        {
                            'name': result['gate'],
                            'status': result['status'],
                            'message': result['message']
                        }
                        for result in gate_results['valid_results']
                    ]
                }
            }

        except Exception as e:
            logger.error(f"Card check error: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': 'Error during card check',
                'details': {'error': str(e)}
            }

    def _format_status_message(self, gate_results: Dict[str, Any]) -> str:
        """Format status message for response"""
        valid_count = gate_results['valid_count']
        total = len(gate_results['valid_results'])

        if valid_count > 0:
            return f"✅ Card Valid - Passed {valid_count}/{total} checks"
        return "❌ Card Invalid - Failed all checks"

    def _check_test_card(self, card: str) -> Dict[str, Any]:
        """Check if card is a test card"""
        for gate, cards in self.test_cards.items():
            if card in cards:
                return {
                    'status': 'test_card',
                    'message': '⚠️ Test Card Detected',
                    'details': {
                        'type': f"{gate.title()} Test Card",
                        'is_test': True
                    }
                }
        return {'is_test': False}

    def _calculate_risk_level(self, validation: Dict[str, Any]) -> str:
        """Calculate risk level based on security checks"""
        security_checks = validation.get('security_checks', {})
        risk_factors = sum(0 if check else 1 for check in security_checks.values())

        if risk_factors >= 3:
            return 'High'
        elif risk_factors >= 1:
            return 'Medium'
        return 'Low'

    async def _run_gate_checks(self, card: str, month: str, year: str) -> Dict[str, Any]:
        """Run checks against available payment gateways"""
        gate_tasks = []

        for gate_name, gate_config in GATES.items():
            if gate_config.get('enabled'):
                check_method = getattr(self, f"check_{gate_name.lower()}", None)
                if check_method:
                    gate_tasks.append(check_method(card, month, year))

        if not gate_tasks:
            return {'valid_results': [], 'valid_count': 0}

        results = await asyncio.gather(*gate_tasks, return_exceptions=True)
        valid_results = [r for r in results if isinstance(r, dict)]
        valid_count = sum(1 for r in valid_results if r.get('status') == 'valid')

        return {
            'valid_results': valid_results,
            'valid_count': valid_count
        }

    async def check_stripe(self, card: str, month: str, year: str) -> GateResponse:
        """Enhanced Stripe gateway check with 3DS handling"""
        logger.debug("Starting Stripe gateway check")
        if not self.api_keys['stripe']:
            return {
                'status': 'error',
                'message': '❌ Stripe API key not configured',
                'gate': 'Stripe'
            }

        try:
            headers = {
                'Authorization': f'Bearer {self.api_keys["stripe"]}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': self.ua.random
            }
            data = {
                'card[number]': card,
                'card[exp_month]': month,
                'card[exp_year]': year,
                'card[cvc]': '000'
            }

            async with self.session or aiohttp.ClientSession() as session:
                logger.debug("Sending request to Stripe API")
                async with session.post(
                    GATES['stripe']['url'],
                    headers=headers,
                    data=data
                ) as response:
                    result = await response.json()
                    logger.debug(f"Stripe API response status: {response.status}")

                    if response.status == 200:
                        return {
                            'status': 'valid',
                            'message': '✅ Card valid',
                            'gate': 'Stripe',
                        }

                    # Check for 3DS requirement
                    if 'three_d_secure' in str(result):
                        return {
                            'status': 'pending',
                            'message': '🔄 3DS verification required',
                            'gate': 'Stripe',
                            'requires_3ds': True,
                        }

                    error_msg = result.get('error', {}).get('message', 'Invalid card')
                    return {
                        'status': 'invalid',
                        'message': f"❌ {error_msg}",
                        'gate': 'Stripe',
                        'error_code': result.get('error', {}).get('code')
                    }

        except Exception as e:
            logger.error(f"Stripe check error: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f"⚠️ Error: {str(e)}",
                'gate': 'Stripe'
            }

    async def check_square(self, card: str, month: str, year: str) -> GateResponse:
        """Enhanced Square gateway check with 3DS handling"""
        logger.debug("Starting Square gateway check")
        if not self.api_keys['square']:
            return {
                'status': 'error',
                'message': '❌ Square API key not configured',
                'gate': 'Square'
            }

        try:
            headers = {
                'Square-Version': '2023-06-08',
                'Authorization': f'Bearer {self.api_keys["square"]}',
                'Content-Type': 'application/json',
                'User-Agent': self.ua.random
            }
            data = {
                'source_id': 'cnon:card-nonce-ok',
                'card_details': {
                    'number': card,
                    'expiration_month': month,
                    'expiration_year': year,
                    'cvv': '000'
                },
                'autocomplete': False,
                'verification_token': self._generate_verification_token()
            }

            async with self.session or aiohttp.ClientSession() as session:
                logger.debug("Sending request to Square API")
                async with session.post(
                    GATES['square']['url'],
                    headers=headers,
                    json=data
                ) as response:
                    result = await response.json()
                    logger.debug(f"Square API response status: {response.status}")

                    if response.status == 200:
                        return {
                            'status': 'valid',
                            'message': '✅ Card valid',
                            'gate': 'Square',
                        }

                    # Check for 3DS requirement
                    if 'verification_required' in str(result):
                        return {
                            'status': 'pending',
                            'message': '🔄 3DS verification required',
                            'gate': 'Square',
                            'requires_3ds': True,
                        }

                    error_msg = result.get('errors', [{}])[0].get('detail', 'Invalid card')
                    return {
                        'status': 'invalid',
                        'message': f"❌ {error_msg}",
                        'gate': 'Square',
                        'error_code': result.get('errors', [{}])[0].get('code')
                    }

        except Exception as e:
            logger.error(f"Square check error: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f"⚠️ Error: {str(e)}",
                'gate': 'Square'
            }

    def _generate_verification_token(self) -> str:
        """Generate a verification token for enhanced security"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return f"v1_{timestamp}_{self.ua.random}"