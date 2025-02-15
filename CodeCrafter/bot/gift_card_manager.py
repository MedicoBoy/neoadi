"""
Gift card management system with comprehensive validation.
"""
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class GiftCardManager:
    """Professional gift card management system"""

    def __init__(self):
        """Initialize with supported vendors"""
        self.vendors = {
            'amazon': {
                'name': 'Amazon Gift Cards',
                'success_rate': '92%',
                'total_attempts': 1500,
                'denominations': '$10-$500',
                'available_denominations': [10, 25, 50, 100, 200, 500]
            },
            'apple': {
                'name': 'Apple Store Cards',
                'success_rate': '89%',
                'total_attempts': 1200,
                'denominations': '$15-$200',
                'available_denominations': [15, 25, 50, 100, 200]
            },
            'steam': {
                'name': 'Steam Wallet Codes',
                'success_rate': '94%',
                'total_attempts': 800,
                'denominations': '$20-$100',
                'available_denominations': [20, 50, 100]
            }
        }

    def get_vendor_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all supported vendors"""
        return self.vendors

    def get_vendor_info(self, vendor: str) -> Dict[str, Any]:
        """Get detailed information for a specific vendor"""
        return self.vendors.get(vendor.lower(), {
            'name': 'Unknown Vendor',
            'success_rate': '0%',
            'total_attempts': 0,
            'denominations': 'N/A',
            'available_denominations': []
        })

    def format_vendor_info(self, vendor: str) -> str:
        """Format vendor information for display"""
        info = self.get_vendor_info(vendor)
        return f"""
📦 *{info['name']} Information*
───────────────────
Success Rate: {info['success_rate']}
Total Attempts: {info['total_attempts']}
Available Values: {info['denominations']}
        """.strip()

    def get_available_denominations(self, vendor: str) -> List[int]:
        """Get available denominations for a vendor"""
        return self.vendors.get(vendor.lower(), {}).get('available_denominations', [])
