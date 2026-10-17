"""Atomic Redis nonce storage for HMAC replay protection across workers."""
from redis import Redis


class RedisNonceStorage:
    """Store each nonce once using Redis SET NX EX in a single round trip."""

    def __init__(self, redis_client: Redis, key_prefix: str = "hmac_nonce") -> None:
        self._redis = redis_client
        self._key_prefix = key_prefix

    def put_if_absent(self, key: str, value: int, ttl_seconds: int) -> bool:
        """Claim a nonce using the remaining lifetime supplied by byteforge-hmac.

        Preserve the existing key prefix so nonces stored before an upgrade
        still reject replays. Redis errors propagate to the handler, which
        logs the failure and denies authentication.
        """
        # byteforge-hmac 0.2.x uses int(now) and accepts the final second
        # inclusively. Its remaining TTL omits that second; Redis expires
        # at the deadline. Retain one extra second to close that replay gap.
        return bool(self._redis.set(
            f"{self._key_prefix}:{key}", str(value), nx=True, ex=ttl_seconds + 1
        ))
