"""
Enhanced credit card number extrapolation and generation utilities.
"""
import random
import re
import asyncio
from typing import List, Optional
from datetime import datetime
from luhn import verify as luhn_verify

class CCExtrapolator:
    """Professional card number extrapolation and generation"""

    @staticmethod
    def generate_cards_from_bin(bin_number: str, amount: int = 10) -> List[str]:
        """Generate valid card numbers from a BIN"""
        if not bin_number.isdigit() or len(bin_number) != 6:
            return []

        cards = []
        while len(cards) < amount:
            card = bin_number + ''.join(str(random.randint(0, 9)) for _ in range(10))
            if luhn_verify(card):
                month = str(random.randint(1, 12)).zfill(2)
                year = str((datetime.now().year % 100) + random.randint(2, 5)).zfill(2)
                cvv = str(random.randint(100, 999))
                cards.append(f"{card}|{month}|{year}|{cvv}")

        return cards

    @staticmethod
    def generate_by_pattern(pattern: str, amount: int = 10) -> List[str]:
        """Generate cards based on a pattern with wildcards"""
        cards = []
        while len(cards) < amount:
            card = ''
            for char in pattern:
                if char == 'x':
                    card += str(random.randint(0, 9))
                elif char == '#':
                    card += str(len(cards) % 10)
                else:
                    card += char

            if luhn_verify(card):
                month = str(random.randint(1, 12)).zfill(2)
                year = str((datetime.now().year % 100) + random.randint(2, 5)).zfill(2)
                cvv = str(random.randint(100, 999))
                cards.append(f"{card}|{month}|{year}|{cvv}")

        return cards

    @staticmethod
    async def generate_sequence(start_card: str, amount: int = 10) -> List[str]:
        """Generate sequence of valid cards asynchronously"""
        if not start_card.isdigit() or len(start_card) != 16:
            return []

        cards = []
        current = int(start_card)
        tasks = []

        async def check_card(card_num: int) -> Optional[str]:
            card_str = str(card_num).zfill(16)
            if luhn_verify(card_str):
                month = str(random.randint(1, 12)).zfill(2)
                year = str((datetime.now().year % 100) + random.randint(2, 5)).zfill(2)
                cvv = str(random.randint(100, 999))
                return f"{card_str}|{month}|{year}|{cvv}"
            return None

        while len(tasks) < amount * 2:  # Check more cards than needed to ensure we get enough valid ones
            tasks.append(check_card(current))
            current += 1

        results = await asyncio.gather(*tasks)
        cards = [card for card in results if card is not None][:amount]
        return cards

    @staticmethod
    def format_cards(cards: List[str]) -> List[str]:
        """Format generated cards for display"""
        formatted = []
        for card in cards:
            if '|' in card:
                number, month, year, cvv = card.split('|')
                formatted.append(f"{number[:6]}xxxxxx{number[-4:]}|{month}|{year}|{cvv}")
            else:
                formatted.append(f"{card[:6]}xxxxxx{card[-4:]}")
        return formatted

    @staticmethod
    def extrapolate_from_bin(bin_number: str, amount: int = 10, algorithm: str = 'standard') -> List[str]:
        """Generate cards from BIN using specified algorithm"""
        if not bin_number.isdigit() or len(bin_number) != 6:
            return []

        cards = []
        while len(cards) < amount:
            suffix = ''
            if algorithm == 'sequence':
                suffix = str(len(cards)).zfill(10)
            elif algorithm == 'random':
                suffix = ''.join(str(random.randint(0, 9)) for _ in range(10))
            else:  # standard
                suffix = ''.join(str(random.randint(0, 9)) for _ in range(10))

            card = bin_number + suffix
            if luhn_verify(card):
                month = str(random.randint(1, 12)).zfill(2)
                year = str((datetime.now().year % 100) + random.randint(2, 5)).zfill(2)
                cvv = str(random.randint(100, 999))
                cards.append(f"{card}|{month}|{year}|{cvv}")

        return cards