"""
Enhanced credit card utilities with professional validation and security features.
"""
from typing import Dict, List, Optional, Union, Any
from datetime import datetime
from core.validcc import CCValidator

class ValidationFormatter:
    """Format validation results for Telegram messages"""

    @staticmethod
    def format_validation_message(result: Dict[str, Any]) -> str:
        """Format validation result as a professional, structured message"""
        if not result.get('valid', False):
            return f"""❌ VALIDATION FAILED
───────────────────
Error: {result.get('error', 'Unknown error')}"""

        # Primary card information section
        card_info = f"""
💳 CARD VALIDATION REPORT
───────────────────────
CARD DETAILS
• Brand: {result.get('card_type', 'Unknown')}
• Institution: {result.get('issuer', 'Unknown')}
• Region: {result.get('country', 'Unknown')}
• Expiration: {result.get('expires', 'Unknown')}"""

        # Security verification section
        security = result.get('security_checks', {})
        security_info = f"""
SECURITY CHECKS
• Luhn Algorithm: {'✅' if security.get('luhn_valid', False) else '❌'}
• Format Check: {'✅' if security.get('length_valid', False) else '❌'}
• Issuer Check: {'✅' if security.get('has_valid_issuer', False) else '❌'}
• Test Number: {'❌' if security.get('not_test_number', False) else '✅'}"""

        # 3D Secure status section
        vbv = result.get('vbv_status', {})
        vbv_info = f"""
3D SECURE STATUS
• Status: [{vbv.get('status', 'UNKNOWN').upper()}]
• Security Score: {vbv.get('details', {}).get('security_score', 0)}/100
• Risk Level: {vbv.get('details', {}).get('risk_level', 'Unknown')}"""

        # Overall validation status
        validation_status = "VALIDATED ✅" if all(security.values()) else "REQUIRES REVIEW ⚠️"
        status_line = f"\n───────────────────\nSTATUS: {validation_status}"

        return f"{card_info}{security_info}{vbv_info}{status_line}".strip()

# Create singleton instances for global use
validator = CCValidator()
formatter = ValidationFormatter()

# Export necessary classes and functions
__all__ = ['validator', 'formatter', 'format_validation_message']

# For backward compatibility
format_validation_message = formatter.format_validation_message