"""
Configuration management for the Telegram bot.
"""
import os
import logging
from dotenv import load_dotenv
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class Config:
    """Bot configuration container"""
    rate_limit: int
    log_file: str
    session_timeout: int = 3600  # 1 hour default timeout
    max_check_limit: int = 10  # Maximum cards for mass check

def load_config() -> Config:
    """Load configuration from environment variables"""
    load_dotenv()

    rate_limit = int(os.getenv('RATE_LIMIT', '60'))  # requests per minute
    log_file = os.getenv('LOG_FILE', 'logs/bot.log')
    session_timeout = int(os.getenv('SESSION_TIMEOUT', '3600'))
    max_check_limit = int(os.getenv('MAX_CHECK_LIMIT', '10'))

    return Config(
        rate_limit=rate_limit,
        log_file=log_file,
        session_timeout=session_timeout,
        max_check_limit=max_check_limit
    )