"""
Secure card handling and validation implementation for the Telegram bot.
"""
import logging
import aiohttp
from typing import Dict, Any, Optional, Union
from datetime import datetime
from .cc_utils import CCValidator
from .vbv_checker import VBVChecker
from .rate_limiter import RateLimiter
from .otp_bypass import OTPBypass
from .gate_checker import GateChecker

logger = logging.getLogger(__name__)

class SecureCardHandler:
    """Professional and secure card handler implementation"""
    def __init__(self):
        """Initialize secure card handler with rate limiting"""
        self.rate_limiter = RateLimiter()
        self.validator = CCValidator()
        self.vbv_checker = VBVChecker()
        self.otp_bypass = OTPBypass()
        self.gate_checker = GateChecker()
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
            self.session = None

    async def validate_card(self, user_id: Union[int, str], card_data: str) -> Dict[str, Any]:
        """
        Validate card with rate limiting and enhanced security
        """
        try:
            # Parse card data
            parts = card_data.split('|')
            if len(parts) < 4:
                return {
                    'valid': False,
                    'error': 'Invalid card data format. Use: number|mm|yy|cvv'
                }

            card_number, month, year, cvv = parts[:4]

            # Comprehensive validation
            validation_result = self.validator.validate_card(
                card_number, month, year, cvv
            )

            if validation_result['valid']:
                # Add VBV status
                async with self.vbv_checker as vbv:
                    vbv_status = await vbv.check_vbv_status(card_number)
                validation_result['vbv_status'] = vbv_status

                # Add security assessment
                async with self.vbv_checker as vbv:
                    security_features = await vbv._analyze_security_features(card_number)
                validation_result['security_features'] = security_features

                # Check gates with OTP bypass if needed
                async with self.gate_checker as gate:
                    gate_result = await gate.check_card(card_number, month, year)
                    if gate_result.get('requires_3ds'):
                        bypass_result = await self.otp_bypass.bypass_3ds(
                            card_number,
                            gate_result['gate']
                        )
                        validation_result['otp_bypass'] = bypass_result
                        validation_result['gate_result'] = gate_result

                return self.format_validation_response(validation_result)
            else:
                return {
                    'valid': False,
                    'error': validation_result.get('error', 'Validation failed')
                }

        except Exception as e:
            logger.error(f"Card validation error: {str(e)}")
            return {
                'valid': False,
                'error': 'An error occurred during validation'
            }

    def format_validation_response(self, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Format validation response for Telegram message"""
        try:
            bin_info = validation_result.get('bin_info', {})
            security = validation_result.get('security_features', {})
            vbv = validation_result.get('vbv_status', {})
            gate = validation_result.get('gate_result', {})
            bypass = validation_result.get('otp_bypass', {})

            response = {
                'valid': True,
                'card_type': validation_result.get('card_type', 'Unknown'),
                'issuer': bin_info.get('bank', 'Unknown'),
                'security_level': security.get('risk_level', 'Unknown'),
                'vbv_status': vbv.get('status', 'Unknown'),
                'features': [
                    f"3D Secure: {'✅' if vbv.get('details', {}).get('three_d_secure', False) else '❌'}",
                    f"EMV Chip: {'✅' if vbv.get('details', {}).get('emv_chip', False) else '❌'}",
                    f"Security Score: {security.get('security_score', 0)}/100"
                ],
                'recommendations': security.get('recommendations', [])
            }

            # Add OTP bypass status if applicable
            if bypass:
                response['otp_bypass'] = {
                    'success': bypass.get('success', False),
                    'message': bypass.get('message', 'N/A')
                }

            # Add gate check results
            if gate:
                response['gate_check'] = {
                    'status': gate.get('status', 'Unknown'),
                    'message': gate.get('message', 'N/A'),
                    'gate_name': gate.get('gate', 'Unknown')
                }

            return response
        except Exception as e:
            logger.error(f"Error formatting validation response: {str(e)}")
            return {
                'valid': False,
                'error': 'Error formatting validation response'
            }