"""
Utility functions for the Telegram bot.
"""
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

def setup_logging(log_file: str):
    """Setup logging configuration"""
    # Ensure logs directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def sanitize_input(text: str) -> str:
    """Sanitize user input"""
    # Remove potentially dangerous characters
    return ''.join(char for char in text if char.isprintable())

def format_timestamp() -> str:
    """Format current timestamp"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')