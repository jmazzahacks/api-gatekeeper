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
SITE_UUID = '11111111-1111-1111-1111-111111111111'
AEGIS_UUID = 'b8e9dfc0-5ba5-4bbd-a314-cb342eac0f71'
AEGIS_OTHER_UUID = 'aaaaaaaa-1111-2222-3333-444444444444'
EMAIL = 'admin@example.com'


def _user(
    uuid: str = AEGIS_UUID,
    email: str = EMAIL,
    site_uuid: str = SITE_UUID,
) -> User:
    now = int(time.time())
    return User(
        uuid=uuid,
        site_uuid=site_uuid,
        email=email,
        is_verified=True,
        role=UserRole.USER,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def provisioned_admin(clean_db) -> ConsoleAdmin:
    admin = ConsoleAdmin.create_new(email=EMAIL, aegis_uuid=AEGIS_UUID)
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
        assert result.aegis_uuid == AEGIS_UUID
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
        fake_me[BEARER_VALID] = _user(uuid=AEGIS_OTHER_UUID, email='stranger@example.com')
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
        assert second.aegis_uuid == AEGIS_UUID

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


class TestUuidLookup:
    """Aegis phase-3 (UUID-only contract): every lookup is by aegis_uuid."""

    def test_uuid_hit_returns_admin(self, clean_db, provisioned_admin, fake_me):
        """Provisioned admin found by the UUID Aegis /me returned."""
        fake_me[BEARER_VALID] = _user(uuid=AEGIS_UUID)
        auth = AegisAuthenticator(AEGIS_URL, clean_db)

        result = auth.authenticate(BEARER_VALID)

        assert result is not None
        assert result.aegis_uuid == AEGIS_UUID
        assert result.email == EMAIL

    def test_uppercase_uuid_from_aegis_matches_lowercase_row(self, clean_db, provisioned_admin, fake_me):
        """
        Aegis or a middleware could send an uppercase UUID. The DB stores the
        Postgres-canonical lowercase form; a case-sensitive compare would
        refuse the match. The authenticator normalises through uuid.UUID()
        before querying.
        """
        fake_me[BEARER_VALID] = _user(uuid=AEGIS_UUID.upper())
        auth = AegisAuthenticator(AEGIS_URL, clean_db)

        result = auth.authenticate(BEARER_VALID)

        assert result is not None
        assert result.aegis_uuid == AEGIS_UUID

    def test_malformed_uuid_from_aegis_returns_none_not_500(self, clean_db, provisioned_admin, fake_me):
        """
        A garbled uuid from Aegis (e.g. transient bug) must NOT bubble as
        psycopg2.DataError up through authenticate() — the docstring
        promises all failures collapse to None. `_normalize_uuid` drops the
        malformed value BEFORE it reaches the DB query.
        """
        fake_me[BEARER_VALID] = _user(uuid='not-a-uuid')
        auth = AegisAuthenticator(AEGIS_URL, clean_db)

        # Malformed uuid is rejected upstream of the DB query — no exception,
        # just None.
        assert auth.authenticate(BEARER_VALID) is None


class TestConstructor:
    def test_empty_aegis_api_url_raises(self, clean_db):
        with pytest.raises(ValueError):
            AegisAuthenticator('', clean_db)

    def test_none_aegis_api_url_raises(self, clean_db):
        with pytest.raises(ValueError):
            AegisAuthenticator(None, clean_db)
