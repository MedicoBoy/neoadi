"""
Unit tests for enhanced card extrapolation functionality.
"""
import unittest
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.extrapolation import CCExtrapolator
from core.validcc import CCValidator

class TestCCExtrapolator(unittest.TestCase):
    def test_pattern_generation(self):
        """Test pattern-based card generation"""
        pattern = "4532xxxx####1234"
        amount = 5
        cards = CCExtrapolator.generate_by_pattern(pattern, amount)

        self.assertEqual(len(cards), amount)
        for card in cards:
            self.assertTrue(CCValidator.luhn_check(card))
            self.assertEqual(card[:4], "4532")
            self.assertEqual(card[-4:], "1234")

    def test_bin_extrapolation(self):
        """Test BIN-based card generation with different algorithms"""
        bin_number = "453201"
        amount = 5

        # Test standard algorithm
        cards = CCExtrapolator.extrapolate_from_bin(bin_number, amount, "standard")
        self.assertEqual(len(cards), amount)
        for card in cards:
            self.assertTrue(CCValidator.luhn_check(card))
            self.assertTrue(card.startswith(bin_number))

        # Test sequence algorithm
        cards = CCExtrapolator.extrapolate_from_bin(bin_number, amount, "sequence")
        self.assertEqual(len(cards), amount)
        for card in cards:
            self.assertTrue(CCValidator.luhn_check(card))
            self.assertTrue(card.startswith(bin_number))

        # Test random algorithm
        cards = CCExtrapolator.extrapolate_from_bin(bin_number, amount, "random")
        self.assertEqual(len(cards), amount)
        for card in cards:
            self.assertTrue(CCValidator.luhn_check(card))
            self.assertTrue(card.startswith(bin_number))

    async def test_sequence_generation(self):
        """Test sequential card generation"""
        start_card = "4532015112830366"
        amount = 5
        step = 2

        cards = await CCExtrapolator.generate_sequence(start_card, amount, step)
        self.assertEqual(len(cards), amount)

        for i in range(len(cards)):
            self.assertTrue(CCValidator.luhn_check(cards[i]))
            if i > 0:
                # Check if the difference between consecutive cards follows the step
                diff = int(cards[i]) - int(cards[i-1])
                self.assertTrue(diff > 0)  # Should be increasing

    def test_pattern_analysis(self):
        """Test pattern analysis functionality"""
        cards = [
            "4532015112830366",
            "4532015112830374",
            "4532015112830382"
        ]

        pattern = CCExtrapolator.analyze_pattern(cards)
        self.assertEqual(len(pattern), 16)
        self.assertTrue(pattern.startswith("453201"))  # Common prefix

        # Test with invalid input
        self.assertEqual(CCExtrapolator.analyze_pattern([]), '')
        self.assertEqual(CCExtrapolator.analyze_pattern(['1234']), '')

if __name__ == '__main__':
    unittest.main()