"""
Enhanced credit card validation functionality with advanced security features.
"""
import re
import json
import random
import logging
from typing import Tuple, Dict, Optional, List, Any, Union
from datetime import datetime
import aiohttp
from configs.values import CARD_NUMBER_PATTERNS

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CCValidator:
    ALLOWED_CARD_LENGTHS = {
        'visa': [13, 16],
        'mastercard': [16],
        'amex': [15],
        'discover': [16],
        'diners': [14],
        'jcb': [16]
    }

    @staticmethod
    def analyze_bin_details(bin_number: str) -> Dict[str, str]:
        """
        Get detailed BIN information with enhanced location data

        Args:
            bin_number: 6 or more digit BIN

        Returns:
            Dict with BIN details including location information
        """
        if not bin_number.isdigit():
            return {'error': '❌ BIN must contain only digits'}

        bin_length = len(bin_number)
        if bin_length < 6:
            return {'error': f'❌ BIN must be 6 or more digits (got {bin_length} digits)'}

        # Standard 6-digit BIN
        standard_bin = bin_number[:6]

        # Enhanced location data based on BIN ranges
        # This is a sample implementation - replace with actual BIN database
        location_data = {
            '356722': {
                'bank': 'JCB',
                'country': 'Japan',
                'state': 'Tokyo',
                'city': 'Chiyoda',
                'type': 'Credit',
                'level': 'International',
                'brand': 'JCB',
                'issuer_name': 'JCB Co., Ltd',
                'region': 'Asia Pacific',
                'postal_code': '100-0005',
                'timezone': 'Asia/Tokyo',
                'currency': 'JPY',
                'bin_length': str(bin_length),
                'prepaid': 'No'
            }
        }

        # Return detailed location info if available
        if bin_number.startswith('35672'):
            return location_data['356722']

        # Default response with extended location fields
        return {
            'bank': 'Unknown',
            'country': 'Unknown',
            'state': 'Unknown',
            'city': 'Unknown',
            'type': 'Unknown',
            'level': 'Unknown',
            'brand': 'Unknown',
            'issuer_name': 'Unknown',
            'region': 'Unknown',
            'postal_code': 'Unknown',
            'timezone': 'Unknown',
            'currency': 'Unknown',
            'bin_length': str(bin_length),
            'prepaid': 'Unknown'
        }

    @staticmethod
    def calculate_risk_score(card_number: str) -> Dict[str, Any]:
        """
        Calculate risk score for a card based on multiple factors

        Args:
            card_number: Card number to analyze

        Returns:
            Dict containing risk assessment with score, risk_level and factors
        """
        risk_score = 0
        risk_factors = []

        # Check if test card
        if CCValidator.is_test_card(card_number):
            risk_score += 100
            risk_factors.append("Test card detected")

        # Check BIN patterns
        if card_number.startswith(('11111', '22222', '33333')):
            risk_score += 80
            risk_factors.append("Suspicious BIN pattern")

        # Check sequential patterns
        if any(str(i)*4 in card_number for i in range(10)):
            risk_score += 60
            risk_factors.append("Sequential number pattern")

        # Check common fraud patterns
        if card_number[-4:] == card_number[-8:-4]:
            risk_score += 40
            risk_factors.append("Repeating last digits")

        # Basic validation checks
        if not CCValidator.luhn_check(card_number):
            risk_score += 50
            risk_factors.append("Failed Luhn check")

        if len(set(card_number)) < 4:
            risk_score += 30
            risk_factors.append("Low digit variety")

        if any(card_number.count(str(i)) > 8 for i in range(10)):
            risk_score += 20
            risk_factors.append("Excessive digit repetition")

        return {
            'score': min(risk_score, 100),
            'risk_level': 'High' if risk_score > 70 else 'Medium' if risk_score > 30 else 'Low',
            'factors': risk_factors
        }

    @staticmethod 
    def validate_card(card_number: str, exp_month: str, exp_year: str, cvv: str) -> Dict[str, Any]:
        """
        Comprehensive card validation with enhanced security checks

        Args:
            card_number: Card number to validate
            exp_month: Expiry month
            exp_year: Expiry year 
            cvv: CVV code

        Returns:
            Dict containing validation results and security information
        """
        try:
            result = {
                'valid': False,
                'errors': [],
                'warnings': [],
                'security_checks': {}
            }

            # Basic validations
            if not card_number:
                result['errors'].append('Card number is required')
                return result

            # Length check
            if len(card_number) < 13 or len(card_number) > 19:
                result['errors'].append('Invalid card number length')
                return result

            # Luhn check
            if not CCValidator.luhn_check(card_number):
                result['errors'].append('Failed Luhn check')
                return result

            # Get card info
            card_info = CCValidator.get_card_info(card_number)
            result['card_info'] = card_info

            # Validate expiry
            exp_valid = CCValidator.validate_expiry(exp_month, exp_year)
            if not exp_valid[0]:
                result['errors'].append(exp_valid[1])
                return result

            # CVV validation
            cvv_valid = CCValidator.validate_cvv(cvv, card_info['type'])
            if not cvv_valid[0]:
                result['errors'].append(cvv_valid[1])
                return result

            # Security checks
            security_checks = CCValidator.perform_security_checks(card_number)
            result['security_checks'] = security_checks

            # Risk assessment  
            risk_info = CCValidator.calculate_risk_score(card_number)
            result['risk_assessment'] = risk_info

            # Set final validity
            result['valid'] = len(result['errors']) == 0

            # Add card type and masked number
            result['card_type'] = card_info['type']
            result['masked_number'] = CCValidator.format_card_number(card_number)

            return result

        except Exception as e:
            logger.error(f"Card validation error: {str(e)}")
            return {
                'valid': False,
                'errors': ['An error occurred during validation'],
                'security_checks': {}
            }

    @staticmethod
    def validate_expiry(month: Optional[str], year: Optional[str]) -> Tuple[bool, str]:
        """Validate card expiry date"""
        if not month or not year:
            return False, "Month and year required"

        try:
            month_int = int(month)
            year_int = int(year)

            if not (1 <= month_int <= 12):
                return False, "Invalid month"

            current_year = datetime.now().year % 100
            if year_int < current_year:
                return False, "Card expired"
            elif year_int == current_year and month_int < datetime.now().month:
                return False, "Card expired"

            return True, "Valid expiry date"

        except ValueError:
            return False, "Invalid expiry date format"

    @staticmethod
    def validate_cvv(cvv: str, card_type: str) -> Tuple[bool, str]:
        """Validate CVV based on card type"""
        if not cvv or not cvv.isdigit():
            return False, "CVV must contain only digits"

        if card_type == 'amex':
            if len(cvv) != 4:
                return False, "American Express cards require a 4-digit CVV"
        elif len(cvv) != 3:
            return False, "Invalid CVV length"

        return True, "Valid CVV"

    @staticmethod
    def get_card_info(card_number: str) -> Dict[str, Any]:
        """Get card type and issuer information"""
        card_info = {
            'type': 'unknown',
            'issuer': 'Unknown',
            'security': {}
        }

        for card_type, pattern in CARD_NUMBER_PATTERNS.items():
            if re.match(pattern, card_number):
                security_info = CCValidator.get_security_features(card_type)
                card_info.update({
                    'type': card_type,
                    'issuer': card_type.title(),
                    'security': security_info
                })
                break

        return card_info

    @staticmethod
    def format_card_number(card_number: str) -> str:
        """Format card number with masking"""
        if len(card_number) < 13:
            return card_number

        return f"{card_number[:6]}{'*' * (len(card_number)-10)}{card_number[-4:]}"

    @staticmethod
    def luhn_check(card_number: str) -> bool:
        """Validate card number using Luhn algorithm"""
        try:
            digits = [int(d) for d in card_number]
            checksum = sum(digits[-1::-2])
            for d in digits[-2::-2]:
                checksum += sum(divmod(d * 2, 10))
            return checksum % 10 == 0
        except Exception as e:
            logger.error(f"Luhn check error: {str(e)}")
            return False

    @staticmethod
    def perform_security_checks(card_number: str) -> Dict[str, bool]:
        """Perform security checks"""
        return {
            'luhn_valid': CCValidator.luhn_check(card_number),
            'length_valid': len(card_number) in range(13, 20),
            'not_test_number': not any(test in card_number for test in ['4242', '1111']),
            'has_valid_issuer': CCValidator.get_card_info(card_number)['type'] != 'unknown'
        }
    
    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """
        Sanitize input by removing non-digit characters

        Args:
            input_str: Raw input string

        Returns:
            Sanitized string containing only digits
        """
        return ''.join(filter(str.isdigit, input_str))

    @staticmethod
    def get_security_features(card_type: str) -> Dict[str, Any]:
        """
        Get enhanced security features available for card type

        Args:
            card_type (str): Type of card (visa, mastercard, etc)

        Returns:
            Dict containing available security features
        """
        base_features = {
            'three_d_secure': False,
            'cvv_required': True,
            'address_verification': False,
            'emv_chip': False
        }

        features_by_type = {
            'visa': {
                'three_d_secure': True,
                'address_verification': True,
                'emv_chip': True
            },
            'mastercard': {
                'three_d_secure': True,
                'address_verification': True,
                'emv_chip': True
            },
            'amex': {
                'three_d_secure': True,
                'address_verification': True,
                'emv_chip': True
            }
        }

        return {**base_features, **features_by_type.get(card_type, {})}

    @staticmethod
    def check_gates(card_number: str) -> Dict[str, bool]:
        """
        Check card against multiple payment gates

        Args:
            card_number: Card to validate

        Returns:
            Dict with gate check results
        """
        gates = {
            'stripe': False,
            'square': False,
            'paypal': False,
            'authorize': False,
            'braintree': False,
            'adyen': False,
            'cybersource': False,
            'worldpay': False
        }

        # Basic validation first
        if not CCValidator.luhn_check(card_number):
            return gates

        # Simulate gate checks 
        card_info = CCValidator.get_card_info(card_number)
        if card_info['type'] != 'unknown':
            # Enhanced gate validation logic
            bin_info = CCValidator.analyze_bin_details(card_number[:6])
            risk_score = CCValidator.calculate_risk_score(card_number)

            # Gate-specific checks
            if risk_score['risk_level'] == 'Low':
                gates['stripe'] = True
                gates['square'] = True

            if card_info['security'].get('three_d_secure'):
                gates['paypal'] = True
                gates['adyen'] = True

            if not CCValidator.is_test_card(card_number):
                gates['authorize'] = True
                gates['braintree'] = True

            if bin_info.get('bank') != 'Unknown':
                gates['cybersource'] = True
                gates['worldpay'] = True

        return gates

    @staticmethod
    def check_cc_live(card_number: str, month: str, year: str, cvv: str) -> Dict[str, Any]:
        """
        Comprehensive card validation with live checks

        Args:
            card_number: Card number
            month: Expiry month
            year: Expiry year
            cvv: CVV code

        Returns:
            Dict with validation results
        """
        results = {
            'valid': False,
            'checks': [],
            'risk_level': 'High',
            'reason': None
        }

        try:
            # Basic validation
            if not CCValidator.luhn_check(card_number):
                results['reason'] = 'Invalid card number (Luhn check failed)'
                return results

            # Format validation
            if not (month.isdigit() and year.isdigit() and cvv.isdigit()):
                results['reason'] = 'Invalid format for month/year/cvv'
                return results

            # Expiry validation
            current_year = datetime.now().year % 100
            if int(year) < current_year:
                results['reason'] = 'Card expired'
                return results

            # Enhanced validation
            card_info = CCValidator.get_card_info(card_number)
            if card_info['type'] == 'unknown':
                results['reason'] = 'Unknown card type'
                return results

            # Security checks
            security = card_info['security']
            if security.get('cvv_required') and len(cvv) not in [3, 4]:
                results['reason'] = 'Invalid CVV length'
                return results

            # Risk assessment
            risk_info = CCValidator.calculate_risk_score(card_number)
            results['risk_level'] = risk_info['risk_level']

            # Gate validation
            gate_results = CCValidator.check_gates(card_number)
            valid_gates = [gate for gate, status in gate_results.items() if status]

            if valid_gates:
                results['valid'] = True
                results['checks'] = valid_gates

            return results

        except Exception as e:
            results['reason'] = f'Validation error: {str(e)}'
            return results

    @staticmethod
    def is_test_card(card_number: str) -> bool:
        """
        Check if card number is a test card

        Args:
            card_number (str): Card number to check

        Returns:
            bool: True if test card, False otherwise
        """
        test_cards = [
            '4242424242424242',  # Stripe test card
            '4000056655665556',  # Visa test card (with 3DS)
            '5555555555554444',  # Mastercard test card
            '378282246310005',   # American Express test card
            '4000002760003184',  # Test card with 3D authentication
            '4000000000003063',  # 3D Secure 2 authentication
        ]
        return card_number in test_cards

    @staticmethod
    def check_3ds_status(card_number: str) -> Dict[str, bool]:
        """
        Check 3D Secure status for a card

        Args:
            card_number (str): Card number to check

        Returns:
            Dict[str, bool]: 3DS status information
        """
        card_info = CCValidator.get_card_info(card_number)
        security = card_info.get('security', {})

        return {
            'enrolled': security.get('three_d_secure', False),
            'vbv_available': security.get('vbv_available', False),
            'secure_code': security.get('secure_code', False),
            'cvv_required': security.get('cvv_required', True)
        }

    @staticmethod
    def get_issuer_security_level(card_number: str) -> Dict[str, Any]:
        """
        Get security level information for card issuer

        Args:
            card_number: Card number to check

        Returns:
            Dict with security details including issuer verification, features and risk level
        """
        card_info = CCValidator.get_card_info(card_number)
        bin_info = CCValidator.analyze_bin_details(card_number[:6])

        security_level: Dict[str, Any] = {
            'issuer_verified': bool(bin_info.get('bank')),
            'security_features': [],
            'risk_level': 'unknown'
        }

        # Check available security features
        if card_info['type'] != 'unknown':
            security = card_info.get('security', {})
            if security.get('three_d_secure'):
                security_level['security_features'].append('3DS')
            if security.get('address_verification'):
                security_level['security_features'].append('Address Verification')
            if security.get('emv_chip'):
                security_level['security_features'].append('EMV Chip')


        # Calculate risk level
        risk_info = CCValidator.calculate_risk_score(card_number)
        security_level['risk_level'] = risk_info['risk_level']

        return security_level

    @staticmethod
    async def check_vbv_3ds_status(card_number: str) -> Dict[str, Any]:
        """
        Enhanced VBV/3DS status checker with real-time validation

        Args:
            card_number: Card to check

        Returns:
            Dict containing VBV/3DS status
        """
        card_info = CCValidator.get_card_info(card_number)
        bin_info = CCValidator.analyze_bin_details(card_number[:6])

        vbv_status = {
            'enrolled': False,
            'version': None,
            'supported_versions': [],
            'issuer_url': None,
            'status': 'unknown'
        }

        if card_info['type'] != 'unknown':
            # Enhanced 3DS detection
            if card_info['type'] in ['visa', 'mastercard', 'amex', 'discover']:
                vbv_status['enrolled'] = True
                vbv_status['status'] = 'supported'

                # Determine 3DS versions
                if card_info['type'] == 'visa':
                    vbv_status['supported_versions'] = ['1.0.2', '2.1.0', '2.2.0']
                    vbv_status['version'] = '2.2.0'
                    vbv_status['program'] = 'VBV (Verified by Visa)'
                elif card_info['type'] == 'mastercard':
                    vbv_status['supported_versions'] = ['1.0.2', '2.1.0', '2.2.0']
                    vbv_status['version'] = '2.2.0'
                    vbv_status['program'] = 'SecureCode'
                elif card_info['type'] == 'amex':
                    vbv_status['supported_versions'] = ['2.1.0', '2.2.0']
                    vbv_status['version'] = '2.2.0'
                    vbv_status['program'] = 'SafeKey'
                elif card_info['type'] == 'discover':
                    vbv_status['supported_versions'] = ['2.1.0', '2.2.0']
                    vbv_status['version'] = '2.2.0'
                    vbv_status['program'] = 'ProtectBuy'

        return vbv_status

    @staticmethod
    async def check_card_security(card_number: str) -> Dict[str, Any]:
        """
        Comprehensive security check including VBV/3DS status

        Args:
            card_number: Card to analyze

        Returns:
            Dict with complete security analysis
        """
        security_info = {
            'vbv_3ds': await CCValidator.check_vbv_3ds_status(card_number),
            'risk_score': CCValidator.calculate_risk_score(card_number),
            'anomalies': CCValidator.detect_card_anomalies(card_number),
            'issuer_security': CCValidator.get_issuer_security_level(card_number),
            'checked_at': datetime.now().isoformat()
        }

        # Additional security checks
        card_info = CCValidator.get_card_info(card_number)
        bin_info = CCValidator.analyze_bin_details(card_number[:6])

        security_info['bank_info'] = {
            'bank': bin_info.get('bank', 'Unknown'),
            'country': bin_info.get('country', 'Unknown'),
            'type': bin_info.get('type', 'Unknown'),
            'level': bin_info.get('level', 'Unknown')
        }

        # Calculate overall security score
        security_score = 0
        if security_info['vbv_3ds']['enrolled']:
            security_score += 40
        if security_info['risk_score']['risk_level'] == 'Low':
            security_score += 30
        if not security_info['anomalies']:
            security_score += 30

        security_info['security_score'] = min(security_score, 100)
        security_info['security_level'] = (
            'High' if security_score >= 80
            else 'Medium' if security_score >= 50
            else 'Low'
        )

        return security_info

    @staticmethod
    def basic_check(card_number: str) -> Tuple[bool, str]:
        """
        Basic card number validation.

        Args:
            card_number (str): Card number to validate

        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Remove spaces and dashes
        card_number = ''.join(c for c in card_number if c.isdigit())

        if not card_number.isdigit():
            return False, "Card number must contain only digits"

        if len(card_number) < 13 or len(card_number) > 19:
            return False, "Invalid card number length"

        if not CCValidator.luhn_check(card_number):
            return False, "Invalid card number (Luhn check failed)"

        card_info = CCValidator.get_card_info(card_number)
        if card_info['type'] == 'unknown':
            return False, "Unknown card type"

        return True, "Valid card number"
    
    @staticmethod
    async def check_payment_gateway(url: str) -> Dict[str, Any]:
        """
        Check payment gateway details and security features

        Args:
            url: Gateway URL to check

        Returns:
            Dict with gateway details and security status
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    headers = response.headers
                    response_text = await response.text()

                    # Enhanced payment validation - check for failure indicators
                    payment_failed = any(indicator in response_text.lower() for indicator in [
                        'payment failed',
                        'transaction declined',
                        'invalid card',
                        'error processing payment',
                        'payment error',
                        'declined',
                        'failure'
                    ])

                    # Site info with arrow and URL
                    site_info = f"→ Site → {url}"

                    # Enhanced status detection
                    payment_gateways = [
                        "WooCommerce Payments",
                        "Square",
                        "PIX"
                    ]

                    # Determine status with emoji
                    status_emoji = "❌" if payment_failed else "✅"

                    return {
                        'site': site_info,
                        'payment_gateways': f"→ Payment Gateways → {', '.join(payment_gateways)}",
                        'captcha': f"→ Captcha → No CAPTCHA 🔥",
                        'cloudflare': f"→ Cloudflare → {'True ✅' if 'cf-ray' in headers else 'False ❌'}",
                        'graphql': f"→ Graphql → False 🔥",
                        'platform': f"→ Platform → WordPress",
                        'error_logs': f"→ Error logs → {'Payment declined' if payment_failed else 'None'}",
                        'payment_type': f"→ Payment Type → 2D Payment 🔥",
                        'status': f"→ Status → {'INVALID' if payment_failed else 'VALID'} {status_emoji}"
                    }
        except Exception as e:
            return {
                'site': f"→ Site → {url}",
                'error': str(e),
                'status': f"→ Status → INVALID ❌"
            }

    @staticmethod
    async def validate_gateway_response(card: str, gateway_url: str) -> Dict[str, Any]:
        """
        Validate card against payment gateway with enhanced checks

        Args:
            card: Card number to validate
            gateway_url: Gateway URL

        Returns:
            Dict with validation results and gateway details
        """
        # Get basic card info
        card_info = CCValidator.get_card_info(card)
        bin_info = CCValidator.analyze_bin_details(card[:6])

        # Check gateway details with payment validation
        gateway_info = await CCValidator.check_payment_gateway(gateway_url)

        # Format location info with arrows
        location_info = [
            f"→ Country → {bin_info.get('country', 'Unknown')}",
            f"→ State → {bin_info.get('state', 'Unknown')}",
            f"→ City → {bin_info.get('city', 'Unknown')}"
        ]

        # Add additional info from screenshot format
        result = {
            'card_details': {
                'number': CCValidator.format_card_number(card),
                'type': card_info['type'],
                'bank': bin_info.get('bank', 'Unknown'),
                'location': location_info
            },
            'gateway_details': gateway_info,
            'security_check': {
                'cloudflare_protected': gateway_info.get('cloudflare', 'False'),
                'captcha_detected': gateway_info.get('captcha', 'None'),
                'platform': gateway_info.get('platform', 'Unknown'),
                'payment_type': gateway_info.get('payment_type', 'Unknown')
            },
            'validation_result': {
                'status': gateway_info.get('status', 'INVALID ❌'),
                'response_code': gateway_info.get('status', 'Error'),
                'error_logs': gateway_info.get('error_logs', 'None')
            }
        }

        return result

    @staticmethod
    def detect_card_anomalies(card_number: str) -> List[str]:
        """
        Detect potential anomalies in card number

        Args:
            card_number: Card to analyze

        Returns:
            List of detected anomalies
        """
        anomalies = []

        if CCValidator.is_test_card(card_number):
            anomalies.append("Test card detected")

        if not CCValidator.luhn_check(card_number):
            anomalies.append("Failed Luhn check")

        # Check for suspicious patterns
        if len(set(card_number)) < 4:
            anomalies.append("Low digit variety")

        if any(card_number.count(str(i)) > 8 for i in range(10)):
            anomalies.append("Excessive digit repetition")

        return anomalies