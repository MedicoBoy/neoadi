"""
Enhanced credit card extrapolation functionality.
"""
import random
import re
from typing import List, Optional, Tuple, Dict
from datetime import datetime
from core.validcc import CCValidator

class CCExtrapolator:
    @staticmethod
    def generate_by_pattern(pattern: str, amount: int = 10) -> List[str]:
        """
        Generate cards based on a pattern where:
        x = random digit
        ? = preserve digit from original
        # = sequential digit

        Args:
            pattern: Pattern with x, ? and # (e.g., '4532xxxx????1234' or '4532####????1234')
            amount: Number of cards to generate

        Returns:
            List of generated card numbers
        """
        cards = []
        sequence_counter = 0

        while len(cards) < amount:
            card = ''
            for char in pattern:
                if char.lower() == 'x':
                    card += str(random.randint(0, 9))
                elif char == '#':
                    card += str((sequence_counter // 10 ** len(str(sequence_counter))) % 10)
                elif char == '?':
                    card += '0'  # Default to 0 for unknown positions
                else:
                    card += char

            if CCValidator.luhn_check(card):
                cards.append(card)
                sequence_counter += 1

        return cards

    @staticmethod
    def extrapolate_from_bin(bin_number: str, amount: int = 10, algorithm: str = 'standard') -> List[str]:
        """
        Generate valid cards from a BIN using multiple algorithms

        Args:
            bin_number: 6-8 digit BIN
            amount: Number of cards to generate
            algorithm: Algorithm to use ('standard', 'sequence', 'random')

        Returns:
            List of valid card numbers
        """
        if not bin_number.isdigit() or len(bin_number) < 6:
            return []

        if algorithm == 'sequence':
            pattern = f"{bin_number}{'#' * (16 - len(bin_number))}"
        elif algorithm == 'random':
            pattern = f"{bin_number}{'x' * (16 - len(bin_number))}"
        else:  # standard - mix of random and sequential
            mid_length = (16 - len(bin_number)) // 2
            pattern = f"{bin_number}{'#' * mid_length}{'x' * (16 - len(bin_number) - mid_length)}"

        return CCExtrapolator.generate_by_pattern(pattern, amount)

    @staticmethod
    def mass_generate(bins: List[str], amount_per_bin: int = 10) -> Dict[str, List[str]]:
        """
        Generate cards for multiple BINs with advanced options

        Args:
            bins: List of BIN numbers
            amount_per_bin: Number of cards to generate per BIN

        Returns:
            Dictionary containing BIN and its generated cards
        """
        results = {}
        algorithms = ['standard', 'sequence', 'random']

        for bin_number in bins:
            bin_cards = []
            for algo in algorithms:
                cards = CCExtrapolator.extrapolate_from_bin(
                    bin_number, 
                    amount_per_bin // len(algorithms) + (1 if amount_per_bin % len(algorithms) > 0 else 0),
                    algo
                )
                bin_cards.extend(cards)
            if bin_cards:
                results[bin_number] = bin_cards[:amount_per_bin]

        return results

    @staticmethod
    async def generate_sequence(start_card: str, amount: int = 10, step: int = 1) -> List[str]:
        """
        Generate sequence of cards with configurable step

        Args:
            start_card: Starting card number
            amount: Number of cards to generate
            step: Increment step between cards

        Returns:
            List of generated card numbers
        """
        if not start_card.isdigit() or len(start_card) != 16:
            return []

        cards = []
        current = int(start_card)

        while len(cards) < amount:
            card = str(current).zfill(16)
            if CCValidator.luhn_check(card):
                cards.append(card)
            current += step

        return cards

    @staticmethod
    def format_cards(cards: List[str], include_cvv: bool = True, include_date: bool = True) -> List[str]:
        """
        Format generated cards with additional data

        Args:
            cards: List of card numbers
            include_cvv: Whether to add CVV
            include_date: Whether to add expiry date

        Returns:
            List of formatted card strings
        """
        formatted = []
        current_year = datetime.now().year % 100

        for card in cards:
            parts = [card]

            if include_date:
                month = str(random.randint(1, 12)).zfill(2)
                year = str(random.randint(current_year, current_year + 5))
                parts.extend([month, year])

            if include_cvv:
                cvv = str(random.randint(100, 999))
                parts.append(cvv)

            formatted.append('|'.join(parts))

        return formatted

    @staticmethod
    def analyze_pattern(cards: List[str]) -> str:
        """
        Analyze a list of cards to detect patterns

        Args:
            cards: List of card numbers to analyze

        Returns:
            Detected pattern string
        """
        if not cards or len(cards[0]) != 16:
            return ''

        pattern = ['?' for _ in range(16)]
        base = cards[0]

        for i in range(16):
            same = True
            for card in cards[1:]:
                if card[i] != base[i]:
                    same = False
                    break
            if same:
                pattern[i] = base[i]

        return ''.join(pattern)