"""
Social media profile scraping functionality.
"""
import re
from typing import Dict, List, Optional
import aiohttp
from fake_useragent import UserAgent

class SocialScraper:
    def __init__(self):
        self.ua = UserAgent()
        self.session: Optional[aiohttp.ClientSession] = None
        self.patterns = {
            'facebook': r'(?:https?://)?(?:www\.)?facebook\.com/(?:(?:\w)*#!/)?([\w\-]*)?',
            'twitter': r'(?:https?://)?(?:www\.)?twitter\.com/([\w\-]*)',
            'instagram': r'(?:https?://)?(?:www\.)?instagram\.com/([\w\-]*)',
            'linkedin': r'(?:https?://)?(?:[\w]+\.)?linkedin\.com/in/([\w\-]*)',
            'telegram': r'(?:https?://)?(?:t\.me|telegram\.me)/([\w]*)',
            'github': r'(?:https?://)?(?:www\.)?github\.com/([\w\-]*)'
        }

    async def __aenter__(self):
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def extract_profiles(self, text: str) -> Dict[str, List[str]]:
        """
        Extract social media profile links from text.
        """
        profiles = {}
        for platform, pattern in self.patterns.items():
            matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
            profiles[platform] = [match.group(0) for match in matches]
        return profiles

    async def validate_profiles(self, profiles: Dict[str, List[str]]) -> Dict[str, List[Dict[str, str]]]:
        """
        Validate extracted profiles by checking their existence.
        """
        validated = {}
        if not self.session:
            self.session = aiohttp.ClientSession()

        for platform, urls in profiles.items():
            validated[platform] = []
            for url in urls:
                try:
                    headers = {'User-Agent': self.ua.random}
                    async with self.session.get(url, headers=headers) as response:
                        status = 'active' if response.status == 200 else 'inactive'
                        validated[platform].append({
                            'url': url,
                            'status': status,
                            'username': url.split('/')[-1]
                        })
                except Exception:
                    validated[platform].append({
                        'url': url,
                        'status': 'error',
                        'username': url.split('/')[-1]
                    })

        return validated

    def format_results(self, results: Dict[str, List[Dict[str, str]]]) -> str:
        """Format scraping results for Telegram message"""
        response = ["🔍 *Social Media Profiles Found:*\n"]

        for platform, profiles in results.items():
            if profiles:
                response.append(f"*{platform.title()}:*")
                for profile in profiles:
                    status_emoji = '✅' if profile['status'] == 'active' else '❌'
                    response.append(f"{status_emoji} `{profile['url']}`")
                response.append("")

        if len(response) == 1:
            response.append("No profiles found.")

        return "\n".join(response)
