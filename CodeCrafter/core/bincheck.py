"""
BIN checking functionality.
"""
import aiohttp
from typing import Dict, Optional
from fake_useragent import UserAgent
from configs.values import BIN_APIS

class BinChecker:
    def __init__(self):
        """Initialize BIN checker"""
        self.ua = UserAgent()
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def get_bin_info(self, bin_number: str) -> Optional[Dict[str, str]]:
        """
        Get information about a BIN number

        Args:
            bin_number (str): First 6 digits of card number

        Returns:
            Optional[Dict[str, str]]: BIN information or None if lookup fails
        """
        if not bin_number.isdigit() or len(bin_number) != 6:
            return None

        if not self.session:
            self.session = aiohttp.ClientSession()

        for api in BIN_APIS:
            try:
                headers = {'User-Agent': self.ua.random}
                url = api.format(bin_number)

                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'country': str(data.get('country', {}).get('name', 'Unknown')),
                            'bank': str(data.get('bank', {}).get('name', 'Unknown')),
                            'scheme': str(data.get('scheme', 'Unknown')),
                            'type': str(data.get('type', 'Unknown')),
                            'brand': str(data.get('brand', 'Unknown')),
                            'level': str(data.get('level', 'Unknown'))
                        }
            except Exception:
                continue

        return None

    @staticmethod
    def format_bin_info(info: Optional[Dict[str, str]]) -> str:
        """Format BIN information for display"""
        if not info:
            return "❌ BIN information not found"

        return f"""
🏦 *BIN Information:*
├ Brand: {info.get('brand', 'Unknown')}
├ Type: {info.get('type', 'Unknown')}
├ Level: {info.get('level', 'Unknown')}
├ Bank: {info.get('bank', 'Unknown')}
└ Country: {info.get('country', 'Unknown')}
"""