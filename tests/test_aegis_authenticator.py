"""
Unit tests for AegisAuthenticator.

Patches AegisClient.me() with deterministic fakes so we don't hit a real
Aegis instance, and exercises the cache + console_admins lookup against the
real test database.
"""
import time
import pytest

from api_gatekeeper_models import ConsoleAdmin
from byteforge_aegis_client import AegisUnauthorized
from byteforge_aegis_models import User, UserRole

from src.auth import AegisAuthenticator
import src.auth.aegis_authenticator as aegis_auth_module


AEGIS_URL = 'https://aegis.test'
BEARER_VALID = 'tok_valid_abc'
BEARER_OTHER = 'tok_valid_xyz'
BEARER_BAD = 'tok_bad_deadbeef'
AEGIS_USER_ID = 42
AEGIS_OTHER_USER_ID = 99
EMAIL = 'admin@example.com'


def _user(user_id: int = AEGIS_USER_ID, email: str = EMAIL) -> User:
    now = int(time.time())
    return User(
        id=user_id,
        site_id=1,
        email=email,
        is_verified=True,
        role=UserRole.USER,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def provisioned_admin(clean_db) -> ConsoleAdmin:
    admin = ConsoleAdmin.create_new(aegis_user_id=AEGIS_USER_ID, email=EMAIL)
    result = clean_db.create_admin(admin)
    assert result is not None
    return result


@pytest.fixture
def fake_me(monkeypatch):
    """
    Patch AegisClient.me() to resolve based on the currently-set auth token.

    Registers (token -> User or AegisUnauthorized) mappings; the test decides
    what each token resolves to.
    """
    mapping: dict[str, object] = {}

    def fake(self):
        token = self.get_auth_token()
        result = mapping.get(token)
        if result is None:
            raise AegisUnauthorized('unknown token')
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(aegis_auth_module.AegisClient, 'me', fake)
    return mapping


class TestAuthenticateHappyPath:
    def test_valid_token_returns_provisioned_admin(self, clean_db, provisioned_admin, fake_me):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db)

        result = auth.authenticate(BEARER_VALID)

        assert result is not None
        assert result.aegis_user_id == AEGIS_USER_ID
        assert result.email == EMAIL


class TestAuthenticateFailureModes:
    """All failures collapse to None — no oracle between failure modes."""

    def test_empty_token_returns_none(self, clean_db, fake_me):
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        assert auth.authenticate('') is None

    def test_whitespace_token_returns_none(self, clean_db, fake_me):
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        assert auth.authenticate('   ') is None

    def test_aegis_rejects_token_returns_none(self, clean_db, fake_me):
        # BEARER_BAD is not in fake_me mapping, so AegisUnauthorized is raised
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        assert auth.authenticate(BEARER_BAD) is None

    def test_valid_token_but_user_not_admin_returns_none(self, clean_db, fake_me):
        """Aegis says the token is fine, but the user isn't in console_admins."""
        fake_me[BEARER_VALID] = _user(user_id=AEGIS_OTHER_USER_ID, email='stranger@example.com')
        auth = AegisAuthenticator(AEGIS_URL, clean_db)

        assert auth.authenticate(BEARER_VALID) is None

    def test_aegis_transport_error_returns_none(self, clean_db, fake_me):
        """Any non-AegisUnauthorized exception treated as unauthenticated, not 500."""
        fake_me[BEARER_VALID] = RuntimeError('connection refused')
        auth = AegisAuthenticator(AEGIS_URL, clean_db)

        assert auth.authenticate(BEARER_VALID) is None


class TestCacheBehavior:
    def test_cache_hit_skips_aegis_call(self, clean_db, provisioned_admin, fake_me):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db, cache_ttl_seconds=60)

        # Prime the cache
        first = auth.authenticate(BEARER_VALID)
        assert first is not None

        # Remove the mapping — if we hit Aegis again, authentication would fail.
        # The fact that the second call still succeeds proves the cache served it.
        fake_me.pop(BEARER_VALID)
        second = auth.authenticate(BEARER_VALID)

        assert second is not None
        assert second.aegis_user_id == AEGIS_USER_ID

    def test_cache_miss_for_different_token(self, clean_db, provisioned_admin, fake_me):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db, cache_ttl_seconds=60)

        auth.authenticate(BEARER_VALID)

        # Different token — must go back to Aegis, which doesn't know it
        assert auth.authenticate(BEARER_OTHER) is None

    def test_cache_ttl_expiry_refetches(self, clean_db, provisioned_admin, fake_me, monkeypatch):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db, cache_ttl_seconds=30)

        # Prime cache at t=1000
        monkeypatch.setattr(aegis_auth_module.time, 'time', lambda: 1000)
        assert auth.authenticate(BEARER_VALID) is not None

        # Advance clock past TTL and drop mapping — cache should expire, Aegis
        # should be re-called, and it should now fail.
        monkeypatch.setattr(aegis_auth_module.time, 'time', lambda: 1100)
        fake_me.pop(BEARER_VALID)

        assert auth.authenticate(BEARER_VALID) is None

    def test_cache_ttl_zero_disables_cache(self, clean_db, provisioned_admin, fake_me):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db, cache_ttl_seconds=0)

        auth.authenticate(BEARER_VALID)

        # With TTL=0, the second call re-hits Aegis. Remove the mapping and
        # confirm the second call fails.
        fake_me.pop(BEARER_VALID)
        assert auth.authenticate(BEARER_VALID) is None

    def test_negative_results_not_cached(self, clean_db, provisioned_admin, fake_me):
        """Bad token should re-hit Aegis, not be cached as 'None'."""
        auth = AegisAuthenticator(AEGIS_URL, clean_db, cache_ttl_seconds=60)

        # First call: bad token, Aegis rejects
        assert auth.authenticate(BEARER_VALID) is None

        # Now the token becomes valid. Cache would have stored None,
        # but we don't cache negatives, so this should succeed.
        fake_me[BEARER_VALID] = _user()
        assert auth.authenticate(BEARER_VALID) is not None

    def test_invalidate_drops_entry(self, clean_db, provisioned_admin, fake_me):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db, cache_ttl_seconds=60)

        assert auth.authenticate(BEARER_VALID) is not None
        auth.invalidate(BEARER_VALID)

        fake_me.pop(BEARER_VALID)
        assert auth.authenticate(BEARER_VALID) is None


class TestConstructor:
    def test_empty_aegis_api_url_raises(self, clean_db):
        with pytest.raises(ValueError):
            AegisAuthenticator('', clean_db)

    def test_none_aegis_api_url_raises(self, clean_db):
        with pytest.raises(ValueError):
            AegisAuthenticator(None, clean_db)
