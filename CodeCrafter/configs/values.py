"""
Configuration values for the Telegram bot.
"""
from typing import Dict, List

# Card validation patterns
CARD_NUMBER_PATTERNS = {
    'visa': r'^4[0-9]{12}(?:[0-9]{3})?$',
    'mastercard': r'^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$',
    'amex': r'^3[47][0-9]{13}$',
    'discover': r'^6(?:011|5[0-9]{2})[0-9]{12}$',
    'jcb': r'^(?:2131|1800|35\d{3})\d{11}$',
    'diners': r'^3(?:0[0-5]|[68][0-9])[0-9]{11}$'
}

# Payment Gateway Configurations
GATES = {
    'stripe': {
        'name': 'Stripe Gateway',
        'url': 'https://api.stripe.com/v1/tokens',
        'success_rate': 95,
        'response_time': 'Fast',
        'enabled': True,
        'test_mode': True,
        'supports_3ds': True,
        'max_attempts': 3
    },
    'square': {
        'name': 'Square Gateway',
        'url': 'https://connect.squareup.com/v2/payments',
        'success_rate': 90,
        'response_time': 'Medium',
        'enabled': True,
        'test_mode': True,
        'supports_3ds': True,
        'max_attempts': 3
    }
}

# Test card numbers
TEST_CARDS = {
    'visa': [
        '4242424242424242',  # Success
        '4000000000000002',  # Declined
        '4000000000009995',  # Insufficient funds
        '4000000000000069',  # Expired card
        '4000000000000127',  # Incorrect CVC
    ],
    'mastercard': [
        '5555555555554444',  # Success
        '5200000000000007',  # Declined
        '5200000000000114',  # Expired card
    ],
    'amex': [
        '378282246310005',   # Success
        '378282246310116',   # Declined
    ],
    'discover': [
        '6011111111111117',  # Success
        '6011000990139424',  # Declined
    ]
}

# BIN APIs for lookup
BIN_APIS = [
    'https://lookup.binlist.net/{}',
    'https://bins.su/search?action=searchbins&bins={}',
    'https://bincheck.io/bin/{}'
]

# Rate limiting
RATE_LIMIT = 60  # requests per minute
MASS_CHECK_LIMIT = 20  # maximum cards for mass check

# Scraping patterns
SCRAPING_PATTERNS = [
    r'\b\d{16}\b',  # 16 digits
    r'\b\d{13,19}\b',  # 13-19 digits
    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Common format
    r'\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b',  # Spaced format
]

# Security settings
SESSION_TIMEOUT = 3600  # 1 hour
MAX_FAILED_ATTEMPTS = 3

# OTP Settings
OTP_TIMEOUT = 300  # 5 minutes
OTP_LENGTH = 6