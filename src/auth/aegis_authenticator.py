"""
Authenticate incoming bearer tokens as console admins.

Wraps the Aegis `/api/auth/me` introspection endpoint: given a bearer token,
resolves it to an Aegis user, then checks that the user is provisioned in the
local `console_admins` table. Returns a ConsoleAdmin or None.

Callers should treat None as "not authenticated" and respond 401 — do not
distinguish between "bad token" and "token is fine but user isn't an admin"
at the HTTP layer, to avoid leaking which emails are admins.

A small in-memory positive cache (default 60s) keeps per-request Aegis
round-trips out of the hot path for the typical 2-admin console workload.
Negative results are not cached — Aegis's own rate limiter handles abusive
bad-token streams.
"""
import logging
import threading
import time
from typing import Optional

from byteforge_aegis_client import AegisClient, AegisClientConfig, AegisUnauthorized

from api_gatekeeper_models import ConsoleAdmin
from src.database.driver import AuthServiceDB

logger = logging.getLogger(__name__)


class AegisAuthenticator:
    """Resolve a bearer token to a provisioned ConsoleAdmin via Aegis introspection."""

    def __init__(
        self,
        aegis_api_url: str,
        db: AuthServiceDB,
        cache_ttl_seconds: int = 60,
    ) -> None:
        if not aegis_api_url:
            raise ValueError("aegis_api_url is required")
        self._aegis_api_url = aegis_api_url
        self._db = db
        self._cache_ttl = cache_ttl_seconds
        # token -> (ConsoleAdmin, cached_at_epoch)
        self._cache: dict[str, tuple[ConsoleAdmin, int]] = {}
        self._lock = threading.Lock()

    def authenticate(self, bearer_token: str) -> Optional[ConsoleAdmin]:
        """
        Resolve a bearer token to a ConsoleAdmin, or None on any failure.

        Failure modes collapsed to None (no oracle):
        - Empty/blank token
        - Aegis rejected the token (unknown, expired, malformed)
        - Token is valid but the Aegis user isn't provisioned in console_admins
        - Aegis transport error (logged at warning)
        """
        if not bearer_token or not bearer_token.strip():
            return None

        cached = self._cache_get(bearer_token)
        if cached is not None:
            return cached

        user_id = self._introspect(bearer_token)
        if user_id is None:
            return None

        admin = self._db.get_admin_by_aegis_id(user_id)
        if admin is None:
            logger.info(
                "Authenticated Aegis user is not a provisioned console admin",
                extra={'aegis_user_id': user_id},
            )
            return None

        self._cache_put(bearer_token, admin)
        return admin

    def invalidate(self, bearer_token: str) -> None:
        """Drop a token from the cache (e.g. on explicit logout)."""
        with self._lock:
            self._cache.pop(bearer_token, None)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _introspect(self, bearer_token: str) -> Optional[int]:
        """Call Aegis /api/auth/me. Returns user_id on success, None on any failure."""
        client = AegisClient(AegisClientConfig(
            api_url=self._aegis_api_url,
            auto_refresh=False,
        ))
        client.set_auth_token(bearer_token)

        try:
            user = client.me()
        except AegisUnauthorized:
            return None
        except Exception as exc:
            logger.warning(
                "Aegis /me call failed; treating as unauthenticated",
                extra={'error': str(exc)},
            )
            return None

        return user.id

    def _cache_get(self, token: str) -> Optional[ConsoleAdmin]:
        if self._cache_ttl <= 0:
            return None
        now = int(time.time())
        with self._lock:
            entry = self._cache.get(token)
            if entry is None:
                return None
            admin, cached_at = entry
            if now - cached_at > self._cache_ttl:
                self._cache.pop(token, None)
                return None
            return admin

    def _cache_put(self, token: str, admin: ConsoleAdmin) -> None:
        if self._cache_ttl <= 0:
            return
        with self._lock:
            self._cache[token] = (admin, int(time.time()))
