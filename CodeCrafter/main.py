"""
Main entry point for the Telegram bot.
"""
import os
import logging
import signal
import sys
from telegram.ext import Application
from dotenv import load_dotenv
from bot import (
    load_config,
    setup_handlers,
    setup_logging,
    SessionManager,
    RateLimiter
)

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Received shutdown signal, cleaning up...")
    sys.exit(0)

def main():
    """Main function to run the bot"""
    try:
        # Setup signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Load environment variables first
        load_dotenv()

        # Get token directly from environment
        token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not token:
            raise ValueError("TELEGRAM_BOT_TOKEN not set in environment")

        # Load other configuration
        config = load_config()

        # Setup logging
        setup_logging(config.log_file)

        # Initialize components
        session_manager = SessionManager(session_timeout=config.session_timeout)
        rate_limiter = RateLimiter(limit=config.rate_limit, window=60)

        logger.info(f"Rate limiter initialized: {config.rate_limit} requests/minute")

        # Build application with direct token
        application = (
            Application.builder()
            .token(token)
            .build()
        )

        # Setup handlers
        setup_handlers(application)
        logger.info("Starting bot...")

        # Run application
        application.run_polling(drop_pending_updates=True)

    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Bot crashed: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)