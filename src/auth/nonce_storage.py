"""
Redis-based nonce storage for HMAC replay protection.

Provides a dict-like interface for storing and checking nonces,
backed by Redis for multi-instance deployments.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default TTL for nonces - should match or exceed HMAC timestamp tolerance
# Using 10 minutes (600 seconds) to provide buffer beyond typical 5-minute tolerance
DEFAULT_NONCE_TTL = 600


class RedisNonceStorage:
    """
    Redis-backed nonce storage with dict-like interface.

    Stores nonces with automatic expiration to prevent unbounded growth.
    Implements __contains__ and __setitem__ for compatibility with
    byteforge-hmac's HMACAuthenticator.
    """

    def __init__(self, redis_client, ttl: int = DEFAULT_NONCE_TTL, key_prefix: str = "hmac_nonce"):
        """
        Initialize Redis nonce storage.

        Args:
            redis_client: Redis client instance
            ttl: Time-to-live for nonces in seconds (default: 600)
            key_prefix: Prefix for Redis keys (default: "hmac_nonce")
        """
        self._redis = redis_client
        self._ttl = ttl
        self._key_prefix = key_prefix

    def _get_key(self, nonce: str) -> str:
        """Generate Redis key for a nonce."""
        return f"{self._key_prefix}:{nonce}"

    def __contains__(self, nonce: str) -> bool:
        """
        Check if a nonce has been used.

        Args:
            nonce: The nonce to check

        Returns:
            True if nonce exists (replay attack), False if new
        """
        key = self._get_key(nonce)
        return self._redis.exists(key) > 0

    def __setitem__(self, nonce: str, timestamp: int) -> None:
        """
        Store a nonce with its timestamp.

        Args:
            nonce: The nonce to store
            timestamp: The timestamp associated with the nonce
        """
        key = self._get_key(nonce)
        self._redis.setex(key, self._ttl, str(timestamp))

    def __getitem__(self, nonce: str) -> Optional[int]:
        """
        Get the timestamp for a nonce.

        Args:
            nonce: The nonce to look up

        Returns:
            Timestamp if nonce exists, raises KeyError otherwise
        """
        key = self._get_key(nonce)
        value = self._redis.get(key)
        if value is None:
            raise KeyError(nonce)
        return int(value)

    def get(self, nonce: str, default: Optional[int] = None) -> Optional[int]:
        """
        Get the timestamp for a nonce with default.

        Args:
            nonce: The nonce to look up
            default: Default value if nonce not found

        Returns:
            Timestamp if nonce exists, default otherwise
        """
        try:
            return self[nonce]
        except KeyError:
            return default
