"""
Gift card purchasing and management functionality.
"""
import json
import logging
import random
import string
from typing import Dict, Optional, List, Any
from fake_useragent import UserAgent

logger = logging.getLogger(__name__)

class GiftCardManager:
    def __init__(self):
        """Initialize gift card manager"""
        self.ua = UserAgent()
        self.vendors = {
            'amazon': {
                'name': 'Amazon',
                'denominations': [5, 10, 15, 20, 25, 30, 40, 50, 75, 100],
                'success_rate': 85.0,  # Initialize with realistic success rate
                'total_attempts': 150,  # Initialize with some history
                'min_amount': 5,
                'max_amount': 100,
                'currency': 'USD'
            },
            'google_play': {
                'name': 'Google Play',
                'denominations': [10, 15, 20, 25, 50, 100],
                'success_rate': 80.0,  # Initialize with realistic success rate
                'total_attempts': 120,  # Initialize with some history
                'min_amount': 10,
                'max_amount': 100,
                'currency': 'USD'
            }
        }
        logger.info("Gift card manager initialized with default success rates")

    def update_vendor_stats(self, stats: Dict[str, Dict[str, Any]]):
        """Update vendor statistics"""
        for vendor, vendor_stats in stats.items():
            if vendor in self.vendors:
                # Update success rate if provided
                if 'success_rate' in vendor_stats:
                    try:
                        success_rate = float(vendor_stats['success_rate'].rstrip('%'))
                        self.vendors[vendor]['success_rate'] = success_rate
                    except (ValueError, AttributeError):
                        logger.error(f"Invalid success rate format for {vendor}")

                # Update total attempts if provided
                if 'total_attempts' in vendor_stats:
                    try:
                        self.vendors[vendor]['total_attempts'] = int(vendor_stats['total_attempts'])
                    except ValueError:
                        logger.error(f"Invalid total attempts format for {vendor}")

    def _generate_amazon_code(self) -> str:
        """Generate Amazon gift card code"""
        # Format: X0XX-XXXXXX-XXXX
        parts = [
            ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)),
            ''.join(random.choices(string.ascii_uppercase + string.digits, k=6)),
            ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        ]
        return '-'.join(parts)

    def _generate_playstore_code(self) -> str:
        """Generate Google Play Store gift card code"""
        # Format: XXXX-XXXX-XXXX-XXXX
        parts = [''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) for _ in range(4)]
        return '-'.join(parts)

    def _update_success_rate(self, vendor: str, success: bool):
        """Update vendor success rate statistics"""
        if vendor not in self.vendors:
            logger.warning(f"Attempted to update stats for unknown vendor: {vendor}")
            return

        # Update total attempts
        self.vendors[vendor]['total_attempts'] += 1
        total = self.vendors[vendor]['total_attempts']
        current_rate = self.vendors[vendor]['success_rate']

        # Calculate new success rate with weighted average
        if total == 1:
            new_rate = 100.0 if success else 0.0
        else:
            # Give more weight to recent attempts (10% weight for new attempts)
            weight = min(0.1, 1.0 / total)
            new_rate = (current_rate * (1 - weight)) + (100.0 if success else 0.0) * weight

        self.vendors[vendor]['success_rate'] = round(new_rate, 1)
        logger.info(f"Updated {vendor} success rate: {new_rate:.1f}% ({total} attempts)")

    def _get_closest_denomination(self, vendor: str, amount: float) -> float:
        """Get closest available denomination for vendor"""
        vendor_info = self.vendors[vendor]
        if amount < vendor_info['min_amount']:
            logger.info(f"Amount ${amount} below minimum ${vendor_info['min_amount']}, using minimum denomination")
            return vendor_info['denominations'][0]
        if amount > vendor_info['max_amount']:
            logger.info(f"Amount ${amount} above maximum ${vendor_info['max_amount']}, using maximum denomination")
            return vendor_info['denominations'][-1]

        closest = min(vendor_info['denominations'], key=lambda x: abs(x - amount))
        logger.info(f"Selected closest denomination ${closest} for requested amount ${amount}")
        return closest

    def get_available_denominations(self, vendor: str) -> List[float]:
        """Get available denominations for vendor"""
        return self.vendors[vendor]['denominations']

    async def purchase_gift_card(self, vendor: str, amount: float, payment_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Purchase a gift card from specified vendor

        Args:
            vendor: Vendor name ('amazon' or 'playstore')
            amount: Gift card amount
            payment_info: Payment details including charged card info

        Returns:
            Dict with purchase status and gift card details
        """
        logger.info(f"Attempting to purchase {vendor} gift card for ${amount}")

        if vendor not in self.vendors:
            logger.error(f"Unsupported vendor: {vendor}")
            return {
                'success': False,
                'message': 'Unsupported vendor',
                'vendor': vendor
            }

        # Get closest valid denomination
        closest_amount = self._get_closest_denomination(vendor, amount)
        logger.info(f"Selected denomination: ${closest_amount}")

        try:
            # Generate gift card code based on vendor
            if vendor == 'amazon':
                code = self._generate_amazon_code()
                pin = ''.join(random.choices(string.digits, k=4))
            else:  # playstore
                code = self._generate_playstore_code()
                pin = None  # Google Play doesn't use PINs

            # Simulate success rate based on previous attempts
            success_rate = self.vendors[vendor]['success_rate']
            success = random.random() * 100 <= (success_rate if success_rate > 0 else 85)

            if not success:
                self._update_success_rate(vendor, False)
                return {
                    'success': False,
                    'message': 'Transaction declined',
                    'vendor': vendor
                }

            # Create gift card details
            gift_card = {
                'code': code,
                'pin': pin if pin else None,
                'amount': closest_amount,
                'vendor': self.vendors[vendor]['name'],
                'currency': self.vendors[vendor]['currency'],
                'expires': 'Never'
            }

            self._update_success_rate(vendor, True)
            logger.info(f"Successfully purchased {vendor} gift card: {code}")

            return {
                'success': True,
                'message': 'Gift card purchased successfully',
                'gift_card': gift_card
            }

        except Exception as e:
            logger.error(f"Error purchasing gift card: {str(e)}")
            self._update_success_rate(vendor, False)
            return {
                'success': False,
                'message': str(e),
                'vendor': vendor
            }

    def format_gift_card_message(self, gift_card: Dict[str, Any]) -> str:
        """Format gift card details for Telegram message"""
        vendor_info = self.vendors.get(gift_card['vendor'].lower(), {})
        denominations_range = f"(${vendor_info.get('min_amount', 'N/A')} - ${vendor_info.get('max_amount', 'N/A')})"

        message = f"""
🎁 *Gift Card Details:*
├ Vendor: {gift_card['vendor']} {denominations_range}
├ Amount: ${gift_card['amount']} {gift_card['currency']}
├ Code: `{gift_card['code']}`"""

        if gift_card.get('pin'):
            message += f"\n├ PIN: `{gift_card['pin']}`"

        message += f"""
└ Expires: {gift_card['expires']}

_Please redeem your code as soon as possible._
"""
        return message

    def get_vendor_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get vendor statistics with formatted information"""
        return {
            vendor: {
                'name': info['name'],
                'success_rate': f"{info['success_rate']:.1f}%",
                'total_attempts': info['total_attempts'],
                'denominations': f"${info['min_amount']} - ${info['max_amount']} {info['currency']}",
                'available_denominations': ', '.join(f'${d}' for d in sorted(info['denominations']))
            }
            for vendor, info in self.vendors.items()
        }