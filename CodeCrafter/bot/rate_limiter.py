"""
Rate limiting implementation for the Telegram bot.
"""
from collections import defaultdict
import time
import logging
from typing import Dict, List, Tuple, Union

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, limit: int = 60, window: int = 60):
        """
        Initialize rate limiter with configurable settings.

        Args:
            limit (int): Maximum number of requests per window
            window (int): Time window in seconds for rate limiting
        """
        self.limit = limit
        self.window = window
        self.requests: Dict[int, List[float]] = defaultdict(list)
        logger.info(f"Rate limiter initialized with limit {limit} requests per {window} seconds")

    async def check_rate_limit(self, user_id: Union[int, str]) -> Tuple[bool, str]:
        """
        Check if user has exceeded rate limit and provide feedback.

        Args:
            user_id (Union[int, str]): Telegram user ID

        Returns:
            Tuple[bool, str]: (is_allowed, feedback_message)
            - is_allowed: True if request is allowed, False if rate limit exceeded
            - feedback_message: Human-readable status message with remaining requests/time
        """
        try:
            # Convert user_id to int if it's a string
            user_id_int = int(user_id) if isinstance(user_id, str) else user_id
            current_time = time.time()
            user_requests = self.requests[user_id_int]

            # Remove old requests outside the window
            while user_requests and user_requests[0] < current_time - self.window:
                user_requests.pop(0)

            # Calculate remaining requests and time
            remaining = self.limit - len(user_requests)
            if remaining <= 0:
                next_reset = user_requests[0] + self.window - current_time
                message = f"Rate limit exceeded. Please wait {int(next_reset)} seconds."
                logger.warning(f"Rate limit exceeded for user {user_id_int}. Next reset in {int(next_reset)}s")
                return False, message

            # Add new request
            user_requests.append(current_time)
            message = f"Request allowed. {remaining-1} requests remaining in this window."
            logger.debug(f"Request allowed for user {user_id_int}. {remaining-1} requests remaining")
            return True, message

        except (ValueError, TypeError) as e:
            logger.error(f"Invalid user ID format: {user_id} - {str(e)}")
            return False, "Invalid user ID format"

    def get_remaining_requests(self, user_id: Union[int, str]) -> Dict[str, Union[int, float]]:
        """
        Get detailed rate limit status for user.

        Args:
            user_id (Union[int, str]): Telegram user ID

        Returns:
            Dict with:
            - remaining_requests: Number of requests remaining
            - reset_time: Seconds until window resets
            - total_limit: Total requests allowed per window
        """
        try:
            user_id_int = int(user_id) if isinstance(user_id, str) else user_id
            current_time = time.time()
            user_requests = self.requests[user_id_int]

            # Remove old requests
            while user_requests and user_requests[0] < current_time - self.window:
                user_requests.pop(0)

            remaining = max(0, self.limit - len(user_requests))
            reset_time = (user_requests[0] + self.window - current_time) if user_requests else 0

            return {
                'remaining_requests': remaining,
                'reset_time': max(0, reset_time),
                'total_limit': self.limit
            }

        except (ValueError, TypeError):
            logger.error(f"Invalid user ID format in get_remaining_requests: {user_id}")
            return {
                'remaining_requests': 0,
                'reset_time': 0,
                'total_limit': self.limit
            }

    def clear_user(self, user_id: Union[int, str]) -> bool:
        """
        Clear rate limit history for a user.

        Args:
            user_id (Union[int, str]): Telegram user ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            user_id_int = int(user_id) if isinstance(user_id, str) else user_id
            if user_id_int in self.requests:
                del self.requests[user_id_int]
                logger.info(f"Cleared rate limit history for user {user_id_int}")
                return True
            return False
        except (ValueError, TypeError):
            logger.error(f"Invalid user ID format in clear_user: {user_id}")
            return False

    def reset_all(self):
        """Reset rate limits for all users"""
        self.requests.clear()
        logger.info("Reset all rate limits")

    def get_usage_stats(self) -> Dict[str, int]:
        """
        Get rate limiter usage statistics.

        Returns:
            Dict with:
            - total_users: Number of users being tracked
            - total_requests: Total requests across all users
        """
        return {
            'total_users': len(self.requests),
            'total_requests': sum(len(requests) for requests in self.requests.values())
        }