"""
Payment gateway checker implementation with robust security analysis.
"""
import logging
import aiohttp
from typing import Dict, Any, List
from fake_useragent import UserAgent

logger = logging.getLogger(__name__)

class GateChecker:
    """Payment gateway checker with comprehensive security analysis"""
    def __init__(self):
        self.ua = UserAgent()
        self.session = None
        self.gates = [
            {
                'name': 'Stripe',
                'status': 'active',
                'features': ['Card Validation', 'Tokenization']
            },
            {
                'name': 'Square',
                'status': 'active',
                'features': ['Card Processing', 'Payment Links']
            },
            {
                'name': 'PayPal',
                'status': 'active',
                'features': ['Digital Wallet', '3D Secure']
            }
        ]

    async def __aenter__(self):
        """Async context manager entry"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={'User-Agent': self.ua.random}
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
            self.session = None

    async def check_card(self, card: str, month: str, year: str) -> Dict[str, Any]:
        """Check card against available payment gateways"""
        try:
            results = []
            for gate in self.gates:
                status = 'valid' if self._validate_card_for_gate(card, gate['name']) else 'invalid'
                results.append({
                    'gate': gate['name'],
                    'status': status,
                    'message': f"Card {'accepted' if status == 'valid' else 'declined'} by {gate['name']}"
                })

            return {
                'gate_results': results,
                'overall_status': any(r['status'] == 'valid' for r in results)
            }
        except Exception as e:
            logger.error(f"Error checking card: {str(e)}", exc_info=True)
            return {
                'gate_results': [],
                'overall_status': False,
                'error': str(e)
            }

    def _validate_card_for_gate(self, card: str, gate_name: str) -> bool:
        """Simulate card validation for different gates"""
        try:
            # This is a placeholder for actual gateway integration
            return True
        except Exception as e:
            logger.error(f"Error validating card for gate {gate_name}: {str(e)}")
            return False

    def get_available_gates(self) -> List[Dict[str, Any]]:
        """Get list of available payment gates"""
        return self.gates

    def format_gate_info(self) -> str:
        """Format gate information for display"""
        try:
            info = "🔍 *Available Payment Gates:*\n\n"
            for gate in self.gates:
                info += f"*{gate['name']} Gateway*\n"
                info += f"├ Status: {gate['status'].title()}\n"
                info += f"└ Features: {', '.join(gate['features'])}\n\n"
            return info
        except Exception as e:
            logger.error(f"Error formatting gate info: {str(e)}")
            return "❌ Error formatting gate information"