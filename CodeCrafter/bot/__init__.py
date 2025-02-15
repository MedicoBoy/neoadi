"""
Bot package initialization.
"""
import logging
from telegram.ext import CommandHandler, CallbackQueryHandler, Application, ApplicationBuilder
from bot.config import load_config
from bot.handlers import (
    start_command,
    help_command,
    status_command,
    check_command,
    mass_check_command,
    bin_command,
    gates_command,
    button_callback,
    extrapolate_command,
    sequence_command,
    vbv_command,
    security_command,
    error_handler
)
from bot.rate_limiter import RateLimiter
from bot.session import SessionManager
from bot.utils import setup_logging

logger = logging.getLogger(__name__)

def setup_handlers(application: Application):
    """Set up command handlers"""
    # Register error handler first
    application.add_error_handler(error_handler)

    # Core commands
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status_command))

    # Card commands 
    application.add_handler(CommandHandler("check", check_command))
    application.add_handler(CommandHandler("mass", mass_check_command))
    application.add_handler(CommandHandler("bin", bin_command))
    application.add_handler(CommandHandler("extrap", extrapolate_command))
    application.add_handler(CommandHandler("sequence", sequence_command))
    application.add_handler(CommandHandler("vbv", vbv_command))

    # Tool commands
    application.add_handler(CommandHandler("gates", gates_command))
    application.add_handler(CommandHandler("security", security_command))

    # Button callback handler
    application.add_handler(CallbackQueryHandler(button_callback))

    logger.info("All handlers registered successfully")

__all__ = ['load_config', 'setup_handlers', 'RateLimiter', 'SessionManager', 'setup_logging']