"""
Tests for rate limiting functionality.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from src.rate_limiter import RedisBackend, RateLimiter
from src.models.rate_limit import RateLimit


class TestRedisBackend:
    """Tests for Redis backend."""

    def test_increment_and_check_first_request(self):
        """First request should increment to 1 and be allowed."""
        mock_redis = Mock()
        mock_pipeline = Mock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute.return_value = [1, True]  # incr result, expire result

        backend = RedisBackend(mock_redis)
        count, allowed = backend.increment_and_check("client-123", 100)

        assert count == 1
        assert allowed is True
        mock_pipeline.incr.assert_called_once_with("ratelimit:client-123")
        mock_pipeline.expire.assert_called_once()

    def test_increment_and_check_at_limit(self):
        """Request at exact limit should be allowed."""
        mock_redis = Mock()
        mock_pipeline = Mock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute.return_value = [100, True]

        backend = RedisBackend(mock_redis)
        count, allowed = backend.increment_and_check("client-123", 100)

        assert count == 100
        assert allowed is True

    def test_increment_and_check_over_limit(self):
        """Request over limit should be denied."""
        mock_redis = Mock()
        mock_pipeline = Mock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute.return_value = [101, True]

        backend = RedisBackend(mock_redis)
        count, allowed = backend.increment_and_check("client-123", 100)

        assert count == 101
        assert allowed is False

    def test_get_current_count_with_value(self):
        """Should return current count from Redis."""
        mock_redis = Mock()
        mock_redis.get.return_value = "50"

        backend = RedisBackend(mock_redis)
        count = backend.get_current_count("client-123")

        assert count == 50
        mock_redis.get.assert_called_once_with("ratelimit:client-123")

    def test_get_current_count_no_value(self):
        """Should return 0 if no count exists."""
        mock_redis = Mock()
        mock_redis.get.return_value = None

        backend = RedisBackend(mock_redis)
        count = backend.get_current_count("client-123")

        assert count == 0


class TestRateLimiter:
    """Tests for RateLimiter service."""

    def test_check_rate_limit_no_limit_configured(self):
        """Client without rate limit should be allowed (unlimited)."""
        mock_db = Mock()
        mock_db.load_rate_limit_by_client.return_value = None
        mock_backend = Mock()

        limiter = RateLimiter(mock_db, mock_backend)
        allowed, reason = limiter.check_rate_limit("client-123")

        assert allowed is True
        assert reason is None
        mock_backend.increment_and_check.assert_not_called()

    def test_check_rate_limit_under_limit(self):
        """Request under limit should be allowed."""
        mock_db = Mock()
        rate_limit = RateLimit.create_new("client-123", 1000)
        mock_db.load_rate_limit_by_client.return_value = rate_limit

        mock_backend = Mock()
        mock_backend.increment_and_check.return_value = (50, True)

        limiter = RateLimiter(mock_db, mock_backend)
        allowed, reason = limiter.check_rate_limit("client-123")

        assert allowed is True
        assert reason is None

    def test_check_rate_limit_exceeded(self):
        """Request over limit should be denied."""
        mock_db = Mock()
        rate_limit = RateLimit.create_new("client-123", 100)
        mock_db.load_rate_limit_by_client.return_value = rate_limit

        mock_backend = Mock()
        mock_backend.increment_and_check.return_value = (101, False)

        limiter = RateLimiter(mock_db, mock_backend)
        allowed, reason = limiter.check_rate_limit("client-123")

        assert allowed is False
        assert reason == "rate_limit_exceeded"

    def test_config_cache_hit(self):
        """Should use cached config instead of DB lookup."""
        mock_db = Mock()
        rate_limit = RateLimit.create_new("client-123", 1000)
        mock_db.load_rate_limit_by_client.return_value = rate_limit

        mock_backend = Mock()
        mock_backend.increment_and_check.return_value = (1, True)

        limiter = RateLimiter(mock_db, mock_backend)

        # First call loads from DB
        limiter.check_rate_limit("client-123")
        assert mock_db.load_rate_limit_by_client.call_count == 1

        # Second call uses cache
        limiter.check_rate_limit("client-123")
        assert mock_db.load_rate_limit_by_client.call_count == 1

    def test_clear_cache(self):
        """Clear cache should force DB reload."""
        mock_db = Mock()
        rate_limit = RateLimit.create_new("client-123", 1000)
        mock_db.load_rate_limit_by_client.return_value = rate_limit

        mock_backend = Mock()
        mock_backend.increment_and_check.return_value = (1, True)

        limiter = RateLimiter(mock_db, mock_backend)

        # Load into cache
        limiter.check_rate_limit("client-123")
        assert mock_db.load_rate_limit_by_client.call_count == 1

        # Clear cache
        limiter.clear_cache()

        # Should reload from DB
        limiter.check_rate_limit("client-123")
        assert mock_db.load_rate_limit_by_client.call_count == 2

    def test_get_usage_info_with_limit(self):
        """Should return correct usage info for limited client."""
        mock_db = Mock()
        rate_limit = RateLimit.create_new("client-123", 1000)
        mock_db.load_rate_limit_by_client.return_value = rate_limit

        mock_backend = Mock()
        mock_backend.get_current_count.return_value = 250

        limiter = RateLimiter(mock_db, mock_backend)
        info = limiter.get_usage_info("client-123")

        assert info['client_id'] == "client-123"
        assert info['requests_today'] == 250
        assert info['limit_per_day'] == 1000
        assert info['remaining'] == 750
        assert info['is_unlimited'] is False

    def test_get_usage_info_unlimited(self):
        """Should return correct usage info for unlimited client."""
        mock_db = Mock()
        mock_db.load_rate_limit_by_client.return_value = None

        mock_backend = Mock()
        mock_backend.get_current_count.return_value = 5000

        limiter = RateLimiter(mock_db, mock_backend)
        info = limiter.get_usage_info("client-123")

        assert info['client_id'] == "client-123"
        assert info['requests_today'] == 5000
        assert info['limit_per_day'] is None
        assert info['remaining'] is None
        assert info['is_unlimited'] is True


class TestRateLimitModel:
    """Tests for RateLimit model."""

    def test_create_new(self):
        """Should create rate limit with current timestamps."""
        rate_limit = RateLimit.create_new("client-123", 1000)

        assert rate_limit.client_id == "client-123"
        assert rate_limit.requests_per_day == 1000
        assert rate_limit.created_at > 0
        assert rate_limit.updated_at == rate_limit.created_at

    def test_create_with_invalid_limit(self):
        """Should reject non-positive limits."""
        with pytest.raises(ValueError, match="must be positive"):
            RateLimit.create_new("client-123", 0)

        with pytest.raises(ValueError, match="must be positive"):
            RateLimit.create_new("client-123", -1)

    def test_create_without_client_id(self):
        """Should reject empty client_id."""
        with pytest.raises(ValueError, match="client_id is required"):
            RateLimit.create_new("", 1000)

    def test_from_dict(self):
        """Should create from dictionary."""
        data = {
            'client_id': 'client-123',
            'requests_per_day': 500,
            'created_at': 1234567890,
            'updated_at': 1234567900
        }
        rate_limit = RateLimit.from_dict(data)

        assert rate_limit.client_id == "client-123"
        assert rate_limit.requests_per_day == 500
        assert rate_limit.created_at == 1234567890
        assert rate_limit.updated_at == 1234567900

    def test_to_dict(self):
        """Should convert to dictionary."""
        rate_limit = RateLimit(
            client_id="client-123",
            requests_per_day=750,
            created_at=1234567890,
            updated_at=1234567900
        )
        data = rate_limit.to_dict()

        assert data['client_id'] == "client-123"
        assert data['requests_per_day'] == 750
        assert data['created_at'] == 1234567890
        assert data['updated_at'] == 1234567900
