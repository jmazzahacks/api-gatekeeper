"""
Unit tests for RedisNonceStorage.

Tests the Redis-backed nonce storage for HMAC replay protection.
"""
import pytest
from unittest.mock import Mock, MagicMock
from src.auth.nonce_storage import RedisNonceStorage, DEFAULT_NONCE_TTL


class TestRedisNonceStorage:
    """Tests for RedisNonceStorage class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        mock_redis = Mock()
        storage = RedisNonceStorage(mock_redis)

        assert storage._redis == mock_redis
        assert storage._ttl == DEFAULT_NONCE_TTL
        assert storage._key_prefix == "hmac_nonce"

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        mock_redis = Mock()
        storage = RedisNonceStorage(mock_redis, ttl=300, key_prefix="custom_prefix")

        assert storage._ttl == 300
        assert storage._key_prefix == "custom_prefix"

    def test_get_key(self):
        """Test Redis key generation."""
        mock_redis = Mock()
        storage = RedisNonceStorage(mock_redis, key_prefix="test")

        key = storage._get_key("abc123")
        assert key == "test:abc123"

    def test_contains_nonce_exists(self):
        """Test __contains__ returns True when nonce exists."""
        mock_redis = Mock()
        mock_redis.exists.return_value = 1
        storage = RedisNonceStorage(mock_redis)

        result = "test-nonce" in storage

        assert result is True
        mock_redis.exists.assert_called_once_with("hmac_nonce:test-nonce")

    def test_contains_nonce_not_exists(self):
        """Test __contains__ returns False when nonce doesn't exist."""
        mock_redis = Mock()
        mock_redis.exists.return_value = 0
        storage = RedisNonceStorage(mock_redis)

        result = "test-nonce" in storage

        assert result is False
        mock_redis.exists.assert_called_once_with("hmac_nonce:test-nonce")

    def test_setitem_stores_nonce_with_ttl(self):
        """Test __setitem__ stores nonce with correct TTL."""
        mock_redis = Mock()
        storage = RedisNonceStorage(mock_redis, ttl=600)

        storage["test-nonce"] = 1699999999

        mock_redis.setex.assert_called_once_with(
            "hmac_nonce:test-nonce",
            600,
            "1699999999"
        )

    def test_getitem_returns_timestamp(self):
        """Test __getitem__ returns stored timestamp."""
        mock_redis = Mock()
        mock_redis.get.return_value = "1699999999"
        storage = RedisNonceStorage(mock_redis)

        result = storage["test-nonce"]

        assert result == 1699999999
        mock_redis.get.assert_called_once_with("hmac_nonce:test-nonce")

    def test_getitem_raises_keyerror_when_not_found(self):
        """Test __getitem__ raises KeyError when nonce not found."""
        mock_redis = Mock()
        mock_redis.get.return_value = None
        storage = RedisNonceStorage(mock_redis)

        with pytest.raises(KeyError):
            _ = storage["nonexistent-nonce"]

    def test_get_returns_value_when_exists(self):
        """Test get() returns value when nonce exists."""
        mock_redis = Mock()
        mock_redis.get.return_value = "1699999999"
        storage = RedisNonceStorage(mock_redis)

        result = storage.get("test-nonce")

        assert result == 1699999999

    def test_get_returns_default_when_not_exists(self):
        """Test get() returns default when nonce doesn't exist."""
        mock_redis = Mock()
        mock_redis.get.return_value = None
        storage = RedisNonceStorage(mock_redis)

        result = storage.get("nonexistent-nonce", default=0)

        assert result == 0

    def test_get_returns_none_default_when_not_exists(self):
        """Test get() returns None by default when nonce doesn't exist."""
        mock_redis = Mock()
        mock_redis.get.return_value = None
        storage = RedisNonceStorage(mock_redis)

        result = storage.get("nonexistent-nonce")

        assert result is None


class TestRedisNonceStorageIntegration:
    """Integration tests simulating HMAC replay protection flow."""

    def test_replay_protection_flow(self):
        """Test complete replay protection flow."""
        mock_redis = Mock()
        storage = RedisNonceStorage(mock_redis)

        # First request with nonce - should not exist
        mock_redis.exists.return_value = 0
        assert "unique-nonce-123" not in storage

        # Store the nonce after successful authentication
        storage["unique-nonce-123"] = 1699999999
        mock_redis.setex.assert_called_once()

        # Second request with same nonce - should exist (replay attack)
        mock_redis.exists.return_value = 1
        assert "unique-nonce-123" in storage

    def test_multiple_nonces_isolation(self):
        """Test different nonces are isolated."""
        mock_redis = Mock()
        storage = RedisNonceStorage(mock_redis)

        # Check different nonces generate different keys
        storage["nonce-1"] = 100
        storage["nonce-2"] = 200

        calls = mock_redis.setex.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == "hmac_nonce:nonce-1"
        assert calls[1][0][0] == "hmac_nonce:nonce-2"
