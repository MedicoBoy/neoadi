"""
Input validation for the Telegram bot.
"""
import re
from typing import Tuple, Dict, Any
import logging
import aiohttp
import asyncio
from core.validcc import CCValidator

logger = logging.getLogger(__name__)

def validate_input(text: str) -> Tuple[bool, str]:
    """
    Validate user input

    Args:
        text (str): Input text to validate

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not text:
        return False, "Input cannot be empty"

    if len(text) > 4096:
        return False, "Input too long"

    # Check for potentially dangerous patterns
    dangerous_patterns = [
        r"(?i)(?:javascript|data):",  # Potential XSS
        r"(?i)(?:exec|system|eval)\s*\(",  # Code injection
        r"(?:[;|&]|\b(?:ls|cat|nc|curl)\b)",  # Command injection
        r"<[^>]*>",  # HTML/XML tags
        r"\$\{.*?\}",  # Template injection
        r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+",  # SQL injection
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, text):
            return False, "Invalid input detected"

    return True, ""

def validate_card_number(card: str) -> Tuple[bool, str]:
    """
    Validate credit card number format and perform Luhn check

    Args:
        card (str): Card number to validate

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    # Remove spaces and dashes
    card = ''.join(c for c in card if c.isdigit())

    if not card.isdigit():
        return False, "Card number must contain only digits"

    if len(card) < 13 or len(card) > 19:
        return False, "Invalid card number length"

    # Use CCValidator for validation
    if not CCValidator.luhn_check(card):
        return False, "Invalid card number (checksum failed)"

    return True, ""

async def validate_vbv_3ds(card_number: str) -> Dict[str, Any]:
    """
    Validate VBV/3DS status for a card

    Args:
        card_number (str): Card number to check

    Returns:
        Dict[str, Any]: VBV/3DS status information
    """
    try:
        card_number = ''.join(filter(str.isdigit, card_number))
        validator = CCValidator()

        # Basic validation first
        is_valid, error = validate_card_number(card_number)
        if not is_valid:
            return {
                'enrolled': False,
                'version': 'N/A',
                'error': error
            }

        # Use CCValidator's VBV/3DS check
        vbv_status = await validator.check_vbv_3ds_status(card_number)
        return vbv_status

    except Exception as e:
        logger.error(f"VBV/3DS validation error: {str(e)}")
        return {
            'enrolled': False,
            'version': 'N/A',
            'error': str(e)
        }