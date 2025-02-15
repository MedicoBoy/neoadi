"""
Token configuration for the Telegram bot.
"""
import os
import logging

# Setup logging
logger = logging.getLogger(__name__)

# Bot token - Load from environment variable only
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

# API Keys
STRIPE_KEY = os.getenv('STRIPE_SECRET_KEY', '')
SQUARE_KEY = os.getenv('SQUARE_KEY', '')