"""
Rate limiting service with Redis backend.

Uses rolling 24-hour windows for rate limiting.
"""
import time
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# 24 hours in seconds
TTL_24_HOURS = 86400


class RedisBackend:
    """Redis-based rate limit storage."""

    def __init__(self, redis_client):
        """
        Initialize Redis backend.

        Args:
            redis_client: Redis client instance
        """
        self._redis = redis_client

    def _get_key(self, client_id: str) -> str:
        """Generate Redis key for rate limit counter."""
        return f"ratelimit:{client_id}"

    def increment_and_check(self, client_id: str, limit: int) -> tuple[int, bool]:
        """
        Increment counter and check limit using Redis.

        Uses rolling 24-hour window - key expires 24 hours after first request.

        Args:
            client_id: Client identifier
            limit: Maximum requests allowed per 24 hours

        Returns:
            Tuple of (current_count, is_allowed)
        """
        key = self._get_key(client_id)

        pipe = self._redis.pipeline()
        pipe.incr(key)
        # Only set expiry if key is new (NX = only if not exists)
        pipe.expire(key, TTL_24_HOURS, nx=True)

        results = pipe.execute()
        current_count = results[0]

        if current_count > limit:
            return current_count, False

        return current_count, True

    def get_current_count(self, client_id: str) -> int:
        """Get current count from Redis."""
        key = self._get_key(client_id)
        count = self._redis.get(key)
        return int(count) if count else 0


class RateLimiter:
    """
    Rate limiter service that checks and enforces request limits.

    Uses rolling 24-hour windows for rate limiting.
    """

    def __init__(self, db, backend: RedisBackend):
        """
        Initialize rate limiter.

        Args:
            db: Database driver instance for loading rate limit configs
            backend: Rate limit storage backend (Redis)
        """
        self._db = db
        self._backend = backend
        self._config_cache: Dict[str, Optional[int]] = {}
        self._cache_ttl = 300
        self._cache_timestamps: Dict[str, float] = {}

    def _get_limit_for_client(self, client_id: str) -> Optional[int]:
        """
        Get the rate limit configuration for a client.

        Returns None if no limit is configured (unlimited).

        Args:
            client_id: Client identifier

        Returns:
            requests_per_day limit or None if unlimited
        """
        current_time = time.time()
        if client_id in self._config_cache:
            cache_time = self._cache_timestamps.get(client_id, 0)
            if current_time - cache_time < self._cache_ttl:
                return self._config_cache[client_id]

        rate_limit = self._db.load_rate_limit_by_client(client_id)

        if rate_limit:
            limit_value = rate_limit.requests_per_day
        else:
            limit_value = None

        self._config_cache[client_id] = limit_value
        self._cache_timestamps[client_id] = current_time

        return limit_value

    def check_rate_limit(self, client_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if a request is allowed under the rate limit.

        This method increments the counter and checks the limit atomically.

        Args:
            client_id: Client identifier

        Returns:
            Tuple of (is_allowed, reason)
            - (True, None) if allowed
            - (False, "rate_limit_exceeded") if limit exceeded
        """
        limit = self._get_limit_for_client(client_id)

        if limit is None:
            return True, None

        current_count, is_allowed = self._backend.increment_and_check(client_id, limit)

        if not is_allowed:
            logger.warning("Rate limit exceeded", extra={
                'client_id': client_id,
                'limit': limit,
                'current_count': current_count
            })
            return False, "rate_limit_exceeded"

        return True, None

    def get_usage_info(self, client_id: str) -> dict:
        """
        Get current usage information for a client.

        Args:
            client_id: Client identifier

        Returns:
            Dictionary with usage info
        """
        limit = self._get_limit_for_client(client_id)
        current_count = self._backend.get_current_count(client_id)

        return {
            'client_id': client_id,
            'requests_today': current_count,
            'limit_per_day': limit,
            'remaining': (limit - current_count) if limit else None,
            'is_unlimited': limit is None
        }

    def clear_cache(self) -> None:
        """Clear the rate limit configuration cache."""
        self._config_cache.clear()
        self._cache_timestamps.clear()
