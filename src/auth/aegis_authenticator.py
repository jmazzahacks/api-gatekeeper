"""
Authenticate incoming bearer tokens as console admins.

Wraps the Aegis `/api/auth/me` introspection endpoint: given a bearer token,
resolves it to an Aegis user, then checks that the user is provisioned in the
local `console_admins` table by their Aegis UUID. Returns a ConsoleAdmin or
None.

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
import uuid as uuid_mod
from typing import Optional

import psycopg2
from byteforge_aegis_client import AegisClient, AegisClientConfig, AegisUnauthorized
from byteforge_aegis_models import User

from api_gatekeeper_models import ConsoleAdmin
from src.database.driver import AuthServiceDB

logger = logging.getLogger(__name__)


def _normalize_uuid(value: Optional[str]) -> Optional[str]:
    """
    Return the canonical (lowercase, hyphenated) form of a UUID string, or
    None if the input is None/blank/unparseable. Aegis and Postgres both
    canonicalise to lowercase — this normaliser keeps our equality compares
    case- and format-agnostic on both the read and write paths.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        return str(uuid_mod.UUID(value))
    except (ValueError, AttributeError):
        return None


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
        - Aegis returned a User with a missing or unparseable UUID
        - Token is valid but the Aegis user isn't provisioned in console_admins
        - Aegis transport error (logged at warning)
        """
        if not bearer_token or not bearer_token.strip():
            return None

        cached = self._cache_get(bearer_token)
        if cached is not None:
            return cached

        user = self._introspect(bearer_token)
        if user is None:
            return None

        normalized = _normalize_uuid(user.uuid)
        if normalized is None:
            logger.info(
                "Aegis /me returned a user with a missing or malformed uuid; "
                "treating as unauthenticated",
                extra={'aegis_uuid_raw': user.uuid, 'email': user.email},
            )
            return None

        admin = self._lookup_admin(normalized, user.email)
        if admin is None:
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

    def _introspect(self, bearer_token: str) -> Optional[User]:
        """
        Call Aegis /api/auth/me and return the User on success, None on any
        failure.
        """
        client = AegisClient(AegisClientConfig(
            api_url=self._aegis_api_url,
            auto_refresh=False,
        ))
        client.set_auth_token(bearer_token)

        try:
            return client.me()
        except AegisUnauthorized:
            return None
        except Exception as exc:
            logger.warning(
                "Aegis /me call failed; treating as unauthenticated",
                extra={'error': str(exc)},
            )
            return None

    def _lookup_admin(
        self, aegis_uuid: str, aegis_email: str
    ) -> Optional[ConsoleAdmin]:
        """
        Resolve an Aegis UUID to a provisioned ConsoleAdmin.

        `aegis_uuid` is expected to be pre-normalised (lowercase canonical
        form) by `_normalize_uuid` so equality compares are case-insensitive
        and Postgres round-trips are consistent.

        `aegis_email` is Aegis's view of the user's email — carried in the
        "not a provisioned console admin" log line so a support engineer
        answering a "why can't I log in" ticket doesn't have to pivot from
        UUID to email through Aegis.
        """
        try:
            admin = self._db.get_admin_by_aegis_uuid(aegis_uuid)
        except psycopg2.DataError:
            logger.info(
                "Aegis /me returned an unparseable uuid; treating as unauthenticated",
                extra={'aegis_uuid': aegis_uuid, 'email': aegis_email},
            )
            return None
        if admin is None:
            logger.info(
                "Authenticated Aegis user is not a provisioned console admin",
                extra={'aegis_uuid': aegis_uuid, 'email': aegis_email},
            )
        return admin

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
