"""
Session management for the Telegram bot.
"""
from typing import Dict
import time
import logging
import os

logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self, session_timeout: int = 3600):
        """
        Initialize session manager

        Args:
            session_timeout (int): Session timeout in seconds
        """
        self.sessions: Dict[int, float] = {}
        self.session_timeout = session_timeout
        self.user_stats: Dict[int, Dict] = {}  # Track user statistics
        self.owner_id = int(os.getenv('OWNER_ID', '0'))
        self.allowed_users = set()  # Set of allowed user IDs
        logger.info("SessionManager initialized")

    def start_session(self, user_id: int):
        """Start a new session for user"""
        is_new_user = user_id not in self.user_stats
        self.sessions[user_id] = time.time()
        if is_new_user:
            logger.info(f"New user {user_id} started their first session")
            self.user_stats[user_id] = {
                'total_checks': 0,
                'successful_checks': 0,
                'last_active': time.time(),
                'joined_date': time.time()
            }
        logger.info(f"Started {'new' if is_new_user else 'existing'} session for user {user_id}")

    def update_user_stats(self, user_id: int, successful: bool = False):
        """Update user statistics"""
        if user_id not in self.user_stats:
            self.start_session(user_id)

        stats = self.user_stats[user_id]
        stats['total_checks'] += 1
        if successful:
            stats['successful_checks'] += 1
        stats['last_active'] = time.time()
        success_rate = (stats['successful_checks'] / stats['total_checks']) * 100 if stats['total_checks'] > 0 else 0
        logger.info(f"Updated stats for user {user_id}: {stats['successful_checks']}/{stats['total_checks']} successful ({success_rate:.1f}%)")
        self.start_session(user_id)  # Refresh session on activity

    def end_session(self, user_id: int):
        """End user session"""
        if user_id in self.sessions:
            del self.sessions[user_id]
            logger.info(f"Ended session for user {user_id}")

    def has_active_session(self, user_id: int) -> bool:
        """Check if user has active session"""
        if user_id not in self.sessions:
            logger.debug(f"No active session found for user {user_id}")
            return False

        # Check session timeout
        if time.time() - self.sessions[user_id] > self.session_timeout:
            logger.info(f"Session timed out for user {user_id}")
            self.end_session(user_id)
            return False

        return True

    def is_owner(self, user_id: int) -> bool:
        """Check if user is the bot owner"""
        return user_id == self.owner_id

    def is_user_allowed(self, user_id: int) -> bool:
        """Check if user is allowed to use the bot"""
        # Owner is always allowed
        if self.is_owner(user_id):
            return True
        # Check if user is in allowed users list
        return user_id in self.allowed_users

    def add_allowed_user(self, user_id: int):
        """Add a user to allowed users list"""
        if not isinstance(user_id, int):
            raise ValueError("User ID must be an integer")
        self.allowed_users.add(user_id)
        logger.info(f"Added user {user_id} to allowed users list")

    def remove_allowed_user(self, user_id: int):
        """Remove a user from allowed users list"""
        if user_id in self.allowed_users:
            self.allowed_users.remove(user_id)
            logger.info(f"Removed user {user_id} from allowed users list")