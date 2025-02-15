"""
Professional Telegram bot command handlers with robust validation and security features.
"""
import logging
import os
import re
import time
import aiohttp
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    CommandHandler, 
    MessageHandler, 
    CallbackQueryHandler,
    filters, 
    ContextTypes,
    Application
)
from typing import Dict, Any, List
from bot.validators import validate_input, validate_card_number, CCValidator
from bot.cc_utils import validator, formatter
from bot.rate_limiter import RateLimiter
from bot.session import SessionManager
from bot.utils import sanitize_input, format_timestamp
from bot.secure_handler import SecureCardHandler
from bot.vbv_checker import VBVChecker
from bot.gate_checker import GateChecker
from bot.cc_extrapolator import CCExtrapolator
from bot.sms_checker import SMSChecker
from bot.social_scraper import SocialScraper
from bot.netflix_checker import NetflixChecker
from bot.smtp_checker import SMTPChecker

# Setup logging
logger = logging.getLogger(__name__)

# Initialize components
rate_limiter = RateLimiter()
session_manager = SessionManager()

def format_validation_message(response: Dict[str, Any]) -> str:
    """Format validation message for display"""
    return formatter.format_validation_message(response)

# Constants for rate limiting and card limits
MAX_CARDS = 50
MAX_GEN_CARDS = 10

HELP_MESSAGES = {
    'check': """
Use: /check card|mm|yy|cvv
Example: `/check 4532015112830366|09|25|123`

Check single card validity and security status.
""",
    'mass': """
Use: /mass card1|mm|yy|cvv card2|mm|yy|cvv
Example: `/mass 4532015112830366|09|25|123 4532015112830367|10|26|456`

Check multiple cards (max 50).
""",
    'bin': """
Use: /bin <bin_number>
Example: `/bin 453201`

Get detailed BIN information.
""",
    'gen': """
Use: /gen <bin> [amount]
Example: `/gen 453201 10`

Generate valid card numbers.
""",
    'extrap': """
Use: /extrap pattern [amount]
Example: `/extrap 4532xxxx####1234 5`

Generate cards from pattern.
""",
    'vbv': """
Use: /vbv card_number
Example: `/vbv 4532015112830366`

Check VBV/3DS status.
""",
    'help': """
🤖 *Available Commands:*

📌 *Core Commands:*
• /start - Start the bot
• /help - Show help menu
• /status - Check bot status
• /gates - View available gates

📊 *Card Operations:*
• /check - Check single card
• /mass - Check multiple cards
• /bin - Check BIN information
• /gen - Generate cards
• /extrap - Extrapolate cards
• /vbv - Check 3D Secure

⚡ *Quick Tips:*
• All operations are rate-limited
• Max 50 cards per mass check
• Max 10 cards per generation
"""
}

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Enhanced start command with professional welcome message"""
    user = update.effective_user
    welcome_text = f"""
👋 *Welcome to CC Checker Bot!*

*Key Features:*
• Professional card validation
• Mass checking capability
• BIN database access
• Advanced security analysis
• VBV/3DS verification

*Getting Started:*
1. Use /help to see all commands
2. Check /status for bot health
3. View /gates for available gateways

Choose an operation below:
"""

    keyboard = [
        [
            InlineKeyboardButton("💳 Check Card", callback_data='check'),
            InlineKeyboardButton("📊 Mass Check", callback_data='mass')
        ],
        [
            InlineKeyboardButton("🔍 BIN Info", callback_data='bin'),
            InlineKeyboardButton("🎲 Generate", callback_data='gen')
        ],
        [
            InlineKeyboardButton("🔐 VBV Check", callback_data='vbv'),
            InlineKeyboardButton("ℹ️ Help", callback_data='help')
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    try:
        await update.message.reply_text(
            welcome_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
        session_manager.update_user_stats(user.id, successful=True)
    except Exception as e:
        logger.error(f"Start command error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "Welcome! Please use /help to get started.",
            parse_mode='Markdown'
        )

async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Professional card validation command with enhanced security checks"""
    user_id = update.effective_user.id

    # Use improved rate limiter feedback
    is_allowed, message = await rate_limiter.check_rate_limit(user_id)
    if not is_allowed:
        await update.message.reply_text(f"⏳ {message}")
        return

    try:
        if not context.args:
            await update.message.reply_text(
                HELP_MESSAGES['check'],
                parse_mode='Markdown'
            )
            return

        # Parse and validate input
        card_data = ' '.join(context.args)
        if '|' not in card_data:
            raise ValueError("Invalid format. Use: card|mm|yy|cvv")

        parts = card_data.split('|')
        if len(parts) != 4:
            raise ValueError("Invalid format. Use: card|mm|yy|cvv")

        card, month, year, cvv = map(sanitize_input, parts)

        # Initial validation
        if not validate_card_number(card):
            await update.message.reply_text("❌ Invalid card number format.")
            return

        # Send initial processing message
        status_message = await update.message.reply_text(
            "🔄 *Card Validation In Progress*\n└ Performing security checks...",
            parse_mode='Markdown'
        )

        try:
            # Perform comprehensive validation
            async with SecureCardHandler() as handler:
                validation_result = await handler.validate_card(user_id, f"{card}|{month}|{year}|{cvv}")
                response = handler.format_validation_response(validation_result)

            formatted_response = format_validation_message(response)

            # Add rate limit info to response
            rate_info = rate_limiter.get_remaining_requests(user_id)
            formatted_response += f"\n\n_Remaining requests: {rate_info['remaining_requests']}/{rate_info['total_limit']}_"

            await status_message.delete()
            await update.message.reply_text(
                formatted_response,
                parse_mode='Markdown'
            )

        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            await status_message.delete()
            await update.message.reply_text("❌ An error occurred during card validation.")
            return

        # Update user stats
        session_manager.update_user_stats(user_id, successful=validation_result.get('valid', False))

    except ValueError as e:
        await update.message.reply_text(
            f"❌ {str(e)}\n{HELP_MESSAGES['check']}",
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.error(f"Check command error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "❌ An error occurred during validation.",
            parse_mode='Markdown'
        )

async def vbv_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /vbv command with enhanced error handling"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/vbv <card_number>`\n"
                "Example: `/vbv 4532015112830366`\n"
                "Checks 3D Secure status for the card.",
                parse_mode='Markdown'
            )
            return

        card_number = sanitize_input(context.args[0])
        if not validate_card_number(card_number):
            await update.message.reply_text(
                "❌ Invalid card number format.\n"
                "Please provide a valid card number.",
                parse_mode='Markdown'
            )
            return

        status_message = await update.message.reply_text(
            "🔄 *Checking 3D Secure status...*",
            parse_mode='Markdown'
        )

        async with VBVChecker() as checker:
            result = await checker.check_vbv_status(card_number)
            response = checker.format_vbv_response(result)

        await status_message.delete()
        await update.message.reply_text(
            response,
            parse_mode='Markdown'
        )
        session_manager.update_user_stats(user_id, successful=True)

    except Exception as e:
        logger.error(f"VBV check error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "❌ An error occurred checking 3D Secure status.\n"
            "Please try again later.",
            parse_mode='Markdown'
        )
        session_manager.update_user_stats(user_id, successful=False)

def format_3ds_response(result: Dict[str, Any], card_number: str) -> str:
    """Format 3D Secure check response"""
    status = result['status'].upper()
    details = result['details']

    return f"""
🔐 *3D SECURE STATUS*
───────────────────
CARD: `{card_number[:6]}xxxxxx{card_number[-4:]}`
STATUS: [{status}]

*Security Features:*
• 3D Secure: {'✅' if details['three_d_secure'] else '❌'}
• EMV Chip: {'✅' if details['emv_chip'] else '❌'}
• Risk Level: {details['risk_level']}
• Security Score: {details['security_score']}/100

*Recommendations:*
""" + "\n".join(f"• {rec}" for rec in details['recommendations'])

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Professional help command with detailed command descriptions"""
    await update.message.reply_text(
        HELP_MESSAGES['help'],
        parse_mode='Markdown'
    )

def register_handlers(application: Application):
    """Register all command handlers"""
    handlers = [
        CommandHandler("start", start_command),
        CommandHandler("help", help_command),
        CommandHandler("check", check_command),
        CommandHandler("vbv", vbv_command),
        CommandHandler("bin", bin_command),
        CommandHandler("mass", mass_check_command),
        CommandHandler("gen", generate_cards_command),
        CommandHandler("extrap", extrapolate_command),
        CommandHandler("status", status_command),
        CallbackQueryHandler(button_callback),
        CommandHandler("gates", gates_command),
        CommandHandler("otp", otp_check_command),
        CommandHandler("sms", sms_check_command),
        CommandHandler("netflix", netflix_check_command),
        CommandHandler("social", social_scrape_command),
        CommandHandler("gateway", check_gateway_command),
        CommandHandler("security", security_command),
        CommandHandler("proxy", proxy_check_command),
        CommandHandler("smtp", smtp_check_command),
        CommandHandler("sequence", sequence_command),

    ]

    for handler in handlers:
        application.add_handler(handler)

    logger.info("All handlers registered successfully")


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    user_id = query.from_user.id

    help_messages = {
        'check': HELP_MESSAGES['check'],
        'mass': HELP_MESSAGES['mass'],
        'bin': HELP_MESSAGES['bin'],
        'gen': HELP_MESSAGES['gen'],
        'extrap': HELP_MESSAGES['extrap'],
        'vbv': HELP_MESSAGES['vbv'],
        'help': HELP_MESSAGES['help']
    }

    if query.data in help_messages:
        await query.message.reply_text(
            help_messages[query.data],
            parse_mode='Markdown'
        )
    elif query.data == 'gates':
        await gates_command(update, context)
    elif query.data == 'status':
        status_text = await get_status_text(user_id)
        await query.message.reply_text(status_text, parse_mode='Markdown')
    else:
        logger.warning(f"Unknown button callback data: {query.data}")
        await query.message.reply_text("❌ Invalid command")

async def get_status_text(user_id: int) -> str:
    """Get formatted status text"""
    user_stats = session_manager.user_stats.get(user_id, {
        'total_checks': 0,
        'successful_checks': 0,
        'last_active': None
    })

    success_rate = (
        f"{(user_stats['successful_checks'] / user_stats['total_checks'] * 100):.1f}%"
        if user_stats['total_checks'] > 0
        else "N/A"
    )

    return f"""
📊 *Bot Status and Features*

*Core Features:*
├ Bot Status: ✅ Active
├ Rate Limiting: ✅ {rate_limiter.get_remaining_requests(user_id)} requests remaining
└ Session: {'🟢 Active' if session_manager.has_active_session(user_id) else '🔴 Inactive'}

*Card Operations:*
├ Single Check (/check): ✅ Working
│  └ Format: /check <card> <mm> <yy> [amount]
├ Mass Check (/mass): ✅ Working
│  └ Limit: 50 cards per request
├ Card Generator (/gen): ✅ Working
│  └ Limit: 10 cards per request
└ BIN Lookup (/bin): ✅ Working

*Additional Tools:*
├ Extrapolation (/extrap): ✅ Working
├ Sequence Gen (/sequence): ✅ Working
├ SMTP Check (/smtp): ✅ Working
└ Gates Info (/gates): ✅ Working

*Your Statistics:*
├ Total Checks: {user_stats['total_checks']}
├ Successful: {user_stats['successful_checks']}
├ Success Rate: {success_rate}
└ Last Active: {format_timestamp() if user_stats['last_active'] else 'Never'}

*Security:*
├ User ID: `{user_id}`
└ Access Level: {'🔑 Owner' if user_id == 5269532633 else '👤 User'}
"""

async def mass_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /mass command with enhanced validation and security"""
    user_id = update.effective_user.id

    # Enhanced rate limiting - fixed to properly await the async check
    is_allowed = await rate_limiter.check_rate_limit(user_id)
    if not is_allowed:
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    if not context.args:
        await update.message.reply_text(
            "❌ Please provide cards to check.\n"
            "Format: `/mass card1|mm|yy|cvv card2|mm|yy|cvv`\n"
            "Example: `/mass 4532015112830366|09|25|123 4532015112830367|10|26|456`\n"
            f"Max {MAX_CARDS} cards per request",
            parse_mode='Markdown'
        )
        return

    cards = []
    for card_data in context.args[:MAX_CARDS]:  # Limit to MAX_CARDS]:  # Limit to MAX_CARDS
        parts = card_data.split('|')
        if len(parts) >= 4:
            card, month, year, cvv = parts[:4]
            is_valid, error = CCValidator.basic_check(card)
            if is_valid:
                cards.append((card, month, year, cvv))

    if not cards:
        await update.message.reply_text("❌ No valid cards found to check.")
        session_manager.update_user_stats(user_id, successful=False)
        return

    if len(context.args) > MAX_CARDS:
        await update.message.reply_text(f"⚠️ Maximum {MAX_CARDS} cards allowed per request. Checking first {MAX_CARDS} cards.")

    status_message = await update.message.reply_text(f"🔄 Checking {len(cards)} cards...")

    try:
        async with GateChecker() as gate_checker:
            response = "📋 *Mass Check Results:*\n\n"
            valid_cards = 0

            for i, (card, month, year, cvv) in enumerate(cards, 1):
                # Get comprehensive validation results
                check_result = await gate_checker.check_card(card, month, year)
                card_info = CCValidator.get_card_info(card)
                bin_info = CCValidator.analyze_bin_details(card[:6])

                is_valid = any(gate['status'] == 'valid' for gate in check_result.get('gate_results', []))
                status_emoji = '✅' if is_valid else '❌'
                if is_valid:
                    valid_cards += 1

                response += f"*Card {i}:*\n"
                response += f"• Number: `{CCValidator.format_card_number(card)}`\n"
                response += f"• Expiry: {month}/{year}\n"
                response += f"• Type: {card_info['type'].upper()}\n"
                response += f"• Status: {status_emoji}\n"
                response += f"• Location: {bin_info.get('country', 'Unknown')}, {bin_info.get('state', 'Unknown')}\n"
                response += f"• Bank: {bin_info.get('bank', 'Unknown')}\n"
                response += f"• Issuer: {bin_info.get('issuer_name', 'Unknown')}\n"
                response += f"• Currency: {bin_info.get('currency', 'Unknown')}\n"

                # Add gate validation results
                if check_result.get('gate_results'):
                    response += "• Gates:\n"
                    for gate in check_result['gate_results']:
                        gate_emoji = '✅' if gate['status'] == 'valid' else '❌'
                        response += f"  {gate_emoji} {gate['gate']}: {gate['message']}\n"

                response += "\n"

            # Add summary
            success_rate = (valid_cards / len(cards)) * 100 if cards else 0
            response += f"\n*Summary:*\n"
            response += f"• Total Cards: {len(cards)}\n"
            response += f"• Valid: {valid_cards}\n"
            response += f"• Invalid: {len(cards) - valid_cards}\n"
            response += f"• Success Rate: {success_rate:.1f}%\n"

            # Update user stats
            session_manager.update_user_stats(user_id, successful=(valid_cards > 0))

            await status_message.delete()
            await update.message.reply_text(response, parse_mode='Markdown')

    except Exception as e:
        logger.error(f"Mass check error: {str(e)}", exc_info=True)
        await status_message.delete()
        await update.message.reply_text("❌ An error occurred while checking cards.")
        session_manager.update_user_stats(user_id, successful=False)

async def otp_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /otp command to check for OTP bypass possibility"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) != 1:
            await update.message.reply_text(
                "❌ Usage: `/otp <card_number>`\n"
                "Example: `/otp 4532015112830366`",
                parse_mode='Markdown'
            )
            return

        card_number = sanitize_input(context.args[0])
        is_valid, error = validate_card_number(card_number)

        if not is_valid:
            await update.message.reply_text(f"❌ {error}")
            return

        status_message = await update.message.reply_text("🔄 Analyzing card security features...")

        # Get comprehensive security analysis
        security_info = CCValidator.get_security_features(card_number)
        risk_assessment = CCValidator.calculate_risk_score(card_number)

        response = [
            "🔒 *Card Security Analysis:*\n",
            f"Card: `{CCValidator.format_card_number(card_number)}`\n",
            "*Security Features:*"
        ]

        features = {
            'three_d_secure': '3D Secure',
            'address_verification': 'Address Verification (AVS)',
            'cvv_required': 'CVV Required',
            'emv_chip': 'EMV Chip'
        }

        for key, label in features.items():
            status = security_info.get(key, False)
            emoji = '✅' if status else '❌'
            response.append(f"• {emoji} {label}")

        response.extend([
            "\n*Risk Assessment:*",
            f"• Level: {risk_assessment['risk_level']}",
            f"• Score: {risk_assessment['risk_score']}/100",
            "\n*Recommendations:*"
        ])

        for recommendation in risk_assessment.get('recommendations', []):
            response.append(f"• {recommendation}")

        await status_message.delete()
        await update.message.reply_text('\n'.join(response), parse_mode='Markdown')
        session_manager.update_user_stats(user_id, successful=True)

    except Exception as e:
        logger.error(f"OTP check error: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ An error occurred while analyzing the card.")
        session_manager.update_user_stats(user_id, successful=False)

async def sms_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /sms command to check SMS/OTP bypass possibility"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/sms <phone_number>`\n"
                "Example: `/sms +1234567890`",
                parse_mode='Markdown'
            )
            return

        phone_number = context.args[0]
        status_message = await update.message.reply_text("🔄 Analyzing SMS security...")

        async with SMSChecker() as checker:
            result = await checker.check_otp_bypass(phone_number)
            response = format_sms_check_result(result)

        await status_message.delete()
        await update.message.reply_text(response, parse_mode='Markdown')
        session_manager.update_user_stats(user_id, successful=True)

    except Exception as e:
        logger.error(f"SMS check error: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ An error occurred while checking SMS security.")
        session_manager.update_user_stats(user_id, successful=False)

async def gates_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /gates command with improved error handling"""
    user_id = update.effective_user.id

    is_allowed, message = await rate_limiter.check_rate_limit(user_id)
    if not is_allowed:
        await update.message.reply_text(f"⏳ {message}")
        return

    status_message = await update.message.reply_text(
        "🔄 *Fetching gateway information...*",
        parse_mode='Markdown'
    )

    try:
        async with GateChecker() as checker:
            gates_info = checker.format_gate_info()
            # Add rate limit info
            rate_info = rate_limiter.get_remaining_requests(user_id)
            gates_info += f"\n_Remaining requests: {rate_info['remaining_requests']}/{rate_info['total_limit']}_"

            await status_message.delete()
            await update.message.reply_text(
                gates_info,
                parse_mode='Markdown'
            )
            session_manager.update_user_stats(user_id, successful=True)
    except Exception as e:
        logger.error(f"Error in gates command: {str(e)}", exc_info=True)
        await status_message.delete()
        await update.message.reply_text(
            "❌ An error occurred while fetching gate information.\n"
            "Please try again later.",
            parse_mode='Markdown'
        )
        session_manager.update_user_stats(user_id, successful=False)

async def extrapolate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /extrap command with enhanced features"""
    user_id = update.effective_user.id
    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) > 3:
            raise ValueError("Invalid arguments")

        pattern = context.args[0]
        amount = min(int(context.args[1]) if len(context.args) > 1 else 10, 50)
        algorithm = context.args[2] if len(context.args) > 2 else 'standard'

        if algorithm not in ['standard', 'sequence', 'random']:
            algorithm = 'standard'

        # Generate cards using enhanced extrapolator
        if re.match(r'^\d{6}', pattern):  # If pattern is a BIN
            cards = CCExtrapolator.extrapolate_from_bin(pattern, amount, algorithm)
        else:
            cards = CCExtrapolator.generate_by_pattern(pattern, amount)

        if not cards:
            await update.message.reply_text("❌ Failed to generate valid cards.")
            return

        # Format response with enhanced information
        response = f"🎲 *Extrapolated Cards ({algorithm}):*\n\n"
        formatted_cards = CCExtrapolator.format_cards(cards)
        for i, card in enumerate(formatted_cards, 1):
            response += f"`{i}. {card}`\n"

        if len(pattern) == 6:  # If BIN was used
            response += f"\n_Generated using BIN {pattern}_"
        else:
            response += f"\n_Generated using pattern {pattern}_"

        await update.message.reply_text(response, parse_mode='Markdown')

    except ValueError:
        await update.message.reply_text(
            "❌ Usage:\n"
            "1. BIN mode: `/extrap <bin> [amount] [algorithm]`\n"
            "   Example: `/extrap 453201 5 sequence`\n\n"
            "2. Pattern mode: `/extrap <pattern> [amount]`\n"
            "   Pattern: Use 'x' for random, '#' for sequence\n"
            "   Example: `/extrap 4532xxxx####1234 5`\n\n"
            "Algorithms: standard, sequence, random",
            parse_mode='Markdown'
        )

async def sequence_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /sequence command with improved error handling"""
    user_id = update.effective_user.id
    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) < 1:
            await update.message.reply_text(
                "❌ Usage: `/sequence <start_card> [amount]`\n"
                "Example: `/sequence 4532015112830366 5`\n"
                "Generates a sequence of valid card numbers.",
                parse_mode='Markdown'
            )
            return

        start_card = sanitize_input(context.args[0])
        amount = min(int(context.args[1]) if len(context.args) > 1 else 10, 50)

        # Validate start card
        if not validate_card_number(start_card):
            await update.message.reply_text("❌ Invalid card number format for sequence start.")
            return

        status_message = await update.message.reply_text(
            "🔄 Generating card sequence...",
            parse_mode='Markdown'
        )

        # Generate sequence using the async method
        cards = await CCExtrapolator.generate_sequence(start_card, amount)
        if not cards:
            await status_message.delete()
            await update.message.reply_text("❌ Failed to generate valid sequence.")
            return

        # Format response
        response = "📋 *Generated Sequence:*\n\n"
        formatted_cards = CCExtrapolator.format_cards(cards)
        for i, card in enumerate(formatted_cards, 1):
            response += f"`{i}. {card}`\n"

        await status_message.delete()
        await update.message.reply_text(response, parse_mode='Markdown')
        session_manager.update_user_stats(user_id, successful=True)

    except ValueError:
        await update.message.reply_text(
            "❌ Usage: `/sequence <start_card> [amount]`\n"
            "Example: `/sequence 4532015112830366 5`\n"
            "Amount must be a number between 1 and 50.",
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.error(f"Sequence command error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "❌ An error occurred while generating the sequence.\n"
            "Please verify your input and try again.",
            parse_mode='Markdown'
        )

async def bin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /bin command"""
    user_id = update.effective_user.id
    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/bin <bin_number>`\n"
                "Example: `/bin 453201`",
                parse_mode='Markdown'
            )
            return

        bin_number = context.args[0]
        from bot.validators import CCValidator
        bin_info = CCValidator.analyze_bin_details(bin_number)

        if not bin_info:
            await update.message.reply_text("❌ Invalid BIN number.")
            return

        response = f"""
ℹ️ *BIN Information:*

BIN: `{bin_number}`
Brand: {bin_info.get('brand','Unknown')}
Type: {bin_info.get('type', 'Unknown')}
Country: {bin_info.get('country', 'Unknown')}
Bank: {bin_info.get('bank', 'Unknown')}
Level: {bin_info.get('level', 'Unknown')}
"""

        await update.message.reply_text(response, parse_mode='Markdown')

    except Exception as e:
        logger.error(f"BIN command error: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ An error occurred while fetching BIN information.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors"""
    logger.error(f"Update {update} caused error {context.error}", exc_info=True)

    error_message = "❌ An error occurred while processing your request."

    if isinstance(context.error, TimeoutError):
        error_message= "⏳ Request timed out. Please try again."
    elif isinstance(context.error, ValueError):
        error_message = "❌ Invalid input format. Please check the command usage with /help"
    elif isinstance(context.error, RuntimeError):
        error_message = "⚠️ Service temporarily unavailable. Please try again later."

    if update and update.effective_message:
        await update.effective_message.reply_text(
            error_message,
            parse_mode='Markdown'
        )

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /status command"""
    user_id = update.effective_user.id
    status_text = await get_status_text(user_id)
    await update.message.reply_text(status_text, parse_mode='Markdown')



async def security_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /security command"""
    user_id = update.effective_user.id
    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return
    
    try:
        if not context.args:
            await update.message.reply_text("Please provide a card number.")
            return
        
        card_number = sanitize_input(context.args[0])
        if not validate_card_number(card_number):
            await update.message.reply_text("Invalid card number.")
            return
        
        security_info = CCValidator.get_security_features(card_number)
        risk_assessment = CCValidator.calculate_risk_score(card_number)
        
        response = f"""
        🔒 *Card Security Analysis:*
        Card: `{CCValidator.format_card_number(card_number)}`
        
        *Security Features:*
        • 3D Secure: {'✅' if security_info.get('three_d_secure', False) else '❌'}
        • Address Verification: {'✅' if security_info.get('address_verification', False) else '❌'}
        • CVV Required: {'✅' if security_info.get('cvv_required', False) else '❌'}
        • EMV Chip: {'✅' if security_info.get('emv_chip', False) else '❌'}
        
        *Risk Assessment:*
        • Risk Level: {risk_assessment['risk_level']}
        • Risk Score: {risk_assessment['risk_score']}/100
        
        *Recommendations:*
        """
        
        for recommendation in risk_assessment.get('recommendations', []):
            response += f"• {recommendation}\n"
            
        await update.message.reply_text(response, parse_mode="Markdown")
    
    except Exception as e:
        logger.error(f"Security command error: {str(e)}", exc_info=True)
        await update.message.reply_text("An error occurred during security analysis.")

async def netflix_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /netflix command"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) != 2:
            await update.message.reply_text(
                "❌ Usage: `/netflix email password`\n"
                "Example: `/netflix user@example.com password123`",
                parse_mode='Markdown'
            )
            return

        email = sanitize_input(context.args[0])
        password = context.args[1]

        # Start checking message
        status_message = await update.message.reply_text(
            "🔄 Checking Netflix account...",
            parse_mode='Markdown'
        )

        async with NetflixChecker() as checker:
            result = await checker.check_account(email, password)
            formatted_result = checker.format_check_result(result, email)

            # Delete processing message and send result
            await status_message.delete()
            await update.message.reply_text(
                formatted_result,
                parse_mode='Markdown'
            )

        # Update user stats
        session_manager.update_user_stats(user_id, successful=(result['status'] == 'valid'))

    except Exception as e:
        logger.error(f"Netflix check error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "❌ An error occurred while checking the account.",
            parse_mode='Markdown'
        )
        session_manager.update_user_stats(user_id, successful=False)

async def social_scrape_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /social command"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    if not update.message.reply_to_message or not update.message.reply_to_message.text:
        await update.message.reply_text(
            "❌ Please reply to a message containing social media links with /social"
        )
        return

    try:
        text = update.message.reply_to_message.text
        status_message = await update.message.reply_text("🔄 Scanning for social media profiles...")

        async with SocialScraper() as scraper:
            # Extract profiles
            profiles = scraper.extract_profiles(text)

            # Validate found profiles
            validated = await scraper.validate_profiles(profiles)

            # Format results
            response = scraper.format_results(validated)

            await status_message.delete()
            await update.message.reply_text(response, parse_mode='Markdown')

            # Update stats based on whether any valid profiles were found
            has_valid = any(
                any(p['status'] == 'active' for p in platform_profiles)
                for platform_profiles in validated.values()
            )
            session_manager.update_user_stats(user_id, successful=has_valid)

    except Exception as e:
        logger.error(f"Error in social scrape: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ An error occurred while scanning for profiles.")
        session_manager.update_user_stats(user_id, successful=False)

async def check_gateway_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /gateway command"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/gateway <url>`\n"
                "Example: `/gateway https://example.com/checkout`",
                parse_mode='Markdown'
            )
            return

        url = context.args[0]
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        status_message = await update.message.reply_text("🔄 Analyzing payment gateway...")

        # Get gateway details
        gateway_info = await CCValidator.check_payment_gateway(url)

        response = [
            "🌐 *Gateway Analysis Result:*\n",
            gateway_info.get('site', 'Error'),
            gateway_info.get('payment_gateways', 'Error'),
            gateway_info.get('captcha', 'Error'),
            gateway_info.get('cloudflare', 'Error'),
            gateway_info.get('graphql', 'Error'),
            gateway_info.get('platform', 'Error'),
            gateway_info.get('error_logs', 'Error'),
            gateway_info.get('payment_type', 'Error'),
            f"\n{gateway_info.get('status', '→ Status → ERROR ❌')}"
        ]

        await status_message.delete()
        await update.message.reply_text('\n'.join(response), parse_mode='Markdown')

    except Exception as e:
        logger.error(f"Gateway check error: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ An error occurred while analyzing the gateway.")

def setup_handlers(application: Application):
    """Set up command handlers"""
    register_handlers(application)
    application.add_handler(CommandHandler("update", update_command))
    application.add_handler(CommandHandler("access", check_access_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scrape_cards_command))
    application.add_handler(error_handler)
    logger.info("All handlers have been set up successfully")

async def update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /update command"""
    user_id = update.effective_user.id
    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    update_text = """
🔄 *Latest Bot Updates and Features*

*Core Features:*
1. Rate Limiting System ✅
   - Maximum 60 requests per minute
   - Per-user tracking implemented

2. Card Operations:
       - Single Check (/check) ✅
         └ Format: /check card|mm|yy|amount
       - Mass Check (/mass) ✅
         └ Limit: 50 cards per request
       - Card Generator (/gen) ✅
         └ Limit: 10 cards per request
       - BIN Lookup (/bin) ✅

    3. Advanced Tools:
       - Extrapolation (/extrap) ✅
       - Sequence Generator (/sequence) ✅
       - SMTP Checker (/smtp) ✅
       - Card Scraper (/scrape) ✅
       - Gates Info (/gates) ✅

    4. Security Features:
       - Session Management ✅
       - User Whitelisting ✅
       - Success Rate Tracking ✅
       - Input Validation ✅

    *Recent Changes:*
    • Updated mass check limit to 50 cards
    • Implemented success rate tracking
    • Enhanced error handling
    • Added detailed success statistics
    • Improved user feedback messages

    *Coming Soon:*    • Transaction success rate tracking
    • Detailed error logging
    • Automated testing system
    • User statistics dashboard

    Use /help for command usage details
    Use /status for current statistics
    """
    await update.message.reply_text(update_text, parse_mode='Markdown')

async def check_access_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /access command to check user's access level"""
    user_id = update.effective_user.id

    # Always allow this command even for non-whitelisted users
    access_text = f"""
🔒 *Access Level Check*

User ID: `{user_id}`
Status: {
    '🔑 Owner' if session_manager.is_owner(user_id)
    else '✅ Whitelisted' if session_manager.is_user_allowed(user_id)
    else '❌ Not Authorized'
}

Available Commands:
"""
    if session_manager.is_owner(user_id):
        access_text += """
*Owner Commands:*
• /whitelist - Add users
• /blacklist - Remove users
• All user commands below
"""

    if session_manager.is_user_allowed(user_id):
        access_text += """
*User Commands:*
• /check - Check cards
• /mass - Mass check
• /gen - Generate cards
• /bin - BIN lookup
• /extrap - Extrapolate cards
• /sequence - Generate sequence
• /smtp - SMTP checker
• /gates - View gates info
"""

    await update.message.reply_text(access_text, parse_mode='Markdown')

async def proxy_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /proxy command"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) < 1:
            await update.message.reply_text(
                "❌ Usage: `/proxy <proxy_string>`\n"
                "Format: `ip:port` or `user:pass@ip:port`\n"
                "Example: `/proxy 192.168.1.1:8080`",
                parse_mode='Markdown'
            )
            return

        proxy = context.args[0]
        status_message = await update.message.reply_text("🔄 Checking proxy...")

        async with aiohttp.ClientSession() as session:
            try:
                start_time = time.time()
                async with session.get('http://ip-api.com/json', proxy=f"http://{proxy}") as response:
                    data = await response.json()
                    ping = round((time.time() - start_time) * 1000)

                    response = [
                        "🌐 *Proxy Check Result:*\n",
                        f"→ IP: `{data.get('query', 'Unknown')}`",
                        f"→ Location: {data.get('country', 'Unknown')}, {data.get('regionName', 'Unknown')}",
                        f"→ ISP: {data.get('isp', 'Unknown')}",
                        f"→ Ping: {ping}ms",
                        f"→ Status: Working ✅"
                    ]
            except Exception:
                response = [
                    "🌐 *Proxy Check Result:*\n",
                    f"→ Proxy: `{proxy}`",
                    f"→ Status: Not Working ❌",
                    f"→ Error: Connection failed"
                ]

        await status_message.delete()
        await update.message.reply_text('\n'.join(response), parse_mode='Markdown')

    except Exception as e:
        logger.error(f"Proxy check error: {str(e)}", exc_info=True)
        await update.message.reply_text("❌ An error occurred while checking the proxy.")

async def scrape_cards_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle card scraping from text"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("Rate limit exceeded. Please try again later.")
        return
    
    try:
        text = update.message.text
        extracted_cards = CCValidator.extract_cards(text)
        if not extracted_cards:
            await update.message.reply_text("No cards found in the text.")
            return
        
        response = "Found cards:\n"
        for card in extracted_cards:
            response += f"- {card}\n"
        await update.message.reply_text(response)
        
    except Exception as e:
        logger.error(f"Card scraping error: {e}")
        await update.message.reply_text("Error during card scraping.")

async def generate_cards_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /gen command"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) > 2:
            await update.message.reply_text(
                "❌ Usage: `/gen <bin> [amount]`\n"
                "Example: `/gen 453201 5`\n"
                f"Maximum {MAX_GEN_CARDS} cards per request.",
                parse_mode='Markdown'
            )
            return

        bin_number = context.args[0]
        amount = min(
            int(context.args[1]) if len(context.args) > 1 else MAX_GEN_CARDS,
            MAX_GEN_CARDS
        )

        status_message = await update.message.reply_text(
            "🔄 Generating cards...",
            parse_mode='Markdown'
        )

        cards = CCExtrapolator.generate_cards_from_bin(bin_number, amount)
        if not cards:
            await status_message.delete()
            await update.message.reply_text("❌ Invalid BIN number or no valid cards generated.")
            return

        response = "🎲 *Generated Cards:*\n\n"
        formatted_cards = CCExtrapolator.format_cards(cards)
        for i, card in enumerate(formatted_cards, 1):
            response += f"`{i}. {card}`\n"

        await status_message.delete()
        await update.message.reply_text(response, parse_mode='Markdown')
        session_manager.update_user_stats(user_id, successful=True)

    except ValueError:
        await update.message.reply_text(
            "❌ Invalid input. Please provide a valid BIN and amount.",
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.error(f"Generate cards error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "❌ An error occurred while generating cards.\n"
            "Please try again later.",
            parse_mode='Markdown'
        )

async def smtp_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /smtp command"""
    user_id = update.effective_user.id

    if not await rate_limiter.check_rate_limit(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Please try again later.")
        return

    try:
        if not context.args or len(context.args) != 2:
            await update.message.reply_text(
                "❌ Usage: `/smtp <host> <port>`\n"
                "Example: `/smtp smtp.gmail.com 587`",
                parse_mode='Markdown'
            )
            return

        host = context.args[0]
        port = int(context.args[1])

        status_message = await update.message.reply_text(
            "🔄 Checking SMTP server...",
            parse_mode='Markdown'
        )

        from bot.smtp_checker import SMTPChecker
        async with SMTPChecker() as checker:
            result = await checker.check_smtp(host, port)

        await status_message.delete()
        await update.message.reply_text(
            result['message'],
            parse_mode='Markdown'
        )
        session_manager.update_user_stats(user_id, successful=result['success'])

    except ValueError:
        await update.message.reply_text(
            "❌ Invalid port number. Please provide a valid port.",
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.error(f"SMTP check error: {str(e)}", exc_info=True)
        await update.message.reply_text(
            "❌ An error occurred while checking the SMTP server.\n"
            "Please try again later.",
            parse_mode='Markdown'
        )

def format_sms_check_result(result: Dict[str, Any]) -> str:
    """Format SMS check result for display"""
    response = [
        "📱 *SMS Security Check Results:*\n",
        f"Status: {result.get('status', 'Unknown').upper()}",
        f"Method: {result.get('method', 'Unknown')}",
        "\n*Security Features:*"
    ]

    features = result.get('features', {})
    for feature, value in features.items():
        emoji = '✅' if value else '❌'
        response.append(f"• {emoji} {feature.replace('_', ' ').title()}")

    if result.get('recommendations'):
        response.append("\n*Recommendations:*")
        for rec in result['recommendations']:
            response.append(f"• {rec}")

    return '\n'.join(response)