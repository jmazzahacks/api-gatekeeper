"""
HMAC authentication handler using byteforge-hmac library.
"""
import logging
import re
import threading
from typing import Optional, Dict
from byteforge_hmac import (
    HMACAuthenticator,
    AuthHeaderParser,
    SecretProvider
)

from src.database.driver import AuthServiceDB
from api_gatekeeper_models import Client

logger = logging.getLogger(__name__)


# Only the canonical 8-4-4-4-12 hyphenated hex form is treated as a UUID.
# Python's uuid.UUID accepts braces, urn: prefix, and 32-char no-dash forms,
# which would route ambiguous legacy strings to the wrong lookup path.
_CANONICAL_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


def _looks_like_uuid(value: str) -> bool:
    """Strict canonical-form check: 36 chars, 8-4-4-4-12 hex with hyphens."""
    return isinstance(value, str) and bool(_CANONICAL_UUID_RE.match(value))


def _resolve_client(db: AuthServiceDB, header_client_id: str) -> Optional[Client]:
    """
    Resolve the client referenced by the HMAC Authorization header.

    Dispatches on whether the header's client_id is a canonical UUID:
      - Canonical UUID → resolve via clients.client_id PK path.
      - Anything else → resolve via clients.legacy_key_id (fallback for
        legacy callers built against the old rba-auth-service, e.g. the
        PodcastGuru mobile app whose client_id is "podcastguru-mobile").

    A canonical UUID-shaped header_client_id NEVER touches the legacy path,
    so the UUID flow is untouched. Non-canonical UUID-ish forms (braces,
    urn:uuid: prefix, 32-char no-dash) fall through to legacy_key_id lookup,
    which is what a legacy caller sending those exact strings would want.

    Args:
        db: Database driver instance
        header_client_id: Raw client_id string parsed from the Authorization
            header

    Returns:
        Matching Client if found, None otherwise
    """
    if _looks_like_uuid(header_client_id):
        return db.load_client_by_id(header_client_id)
    return db.load_client_by_legacy_key_id(header_client_id)


class DatabaseSecretProvider(SecretProvider):
    """
    Secret provider that fetches client secrets from database.

    Integrates byteforge-hmac with our database layer. Accepts both the
    canonical UUID client_id and the legacy string identifier — see
    _resolve_client for the dispatch rule.

    Caches the resolved Client on a thread-local slot during get_secret so
    HMACHandler.authenticate can return the exact Client whose secret
    verified the signature — without a second DB lookup, and without a
    TOCTOU window in which an admin reassigning a legacy_key_id between
    the two lookups would swap the authenticated identity underneath us.
    Safe under gunicorn threaded / gthread workers.
    """

    def __init__(self, db: AuthServiceDB):
        """
        Initialize the secret provider.

        Args:
            db: Database driver instance
        """
        self.db = db
        self._tls = threading.local()

    def get_secret(self, client_id: str) -> Optional[str]:
        """
        Get the shared secret for a client.

        Args:
            client_id: Client identifier from the Authorization header
                (may be a UUID or a legacy_key_id string)

        Returns:
            Shared secret if client exists and has one, None otherwise
        """
        client = _resolve_client(self.db, client_id)
        # Stash under a header-id-keyed slot so take_last_resolved can only
        # hand back the Client whose secret was returned for this exact
        # header value on this thread.
        self._tls.cached_client_id = client_id
        self._tls.cached_client = client
        if client and client.shared_secret:
            return client.shared_secret
        return None

    def take_last_resolved(self, client_id: str) -> Optional[Client]:
        """
        Return the Client from the most recent get_secret call on this
        thread, iff its header client_id matches. Clears the cache on read.

        Returns None if nothing is cached or the cached header doesn't match
        (e.g. get_secret was never called for this request).
        """
        cached_id = getattr(self._tls, 'cached_client_id', None)
        cached_client = getattr(self._tls, 'cached_client', None)
        self._tls.cached_client_id = None
        self._tls.cached_client = None
        if cached_id == client_id:
            return cached_client
        return None


class HMACHandler:
    """
    Handler for HMAC signature authentication.

    Uses byteforge-hmac library for signature validation, timestamp checking,
    and replay protection.

    Signature format: HMAC-SHA256 over {METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{BODY}
    Header format: HMAC client_id="id",timestamp="epoch",nonce="uuid",signature="hex"
    """

    def __init__(
        self,
        db: AuthServiceDB,
        timestamp_tolerance: int = 300,
        nonce_storage: Optional[Dict[str, int]] = None
    ):
        """
        Initialize the HMAC handler.

        Args:
            db: Database driver instance
            timestamp_tolerance: How many seconds old/future timestamps are accepted (default: 5 minutes)
            nonce_storage: Optional dictionary for nonce replay protection.
                          For production with multiple servers, use Redis.
        """
        self.db = db
        self.secret_provider = DatabaseSecretProvider(db)
        self.authenticator = HMACAuthenticator(
            secret_provider=self.secret_provider,
            timestamp_tolerance=timestamp_tolerance,
            nonce_storage=nonce_storage if nonce_storage is not None else {}
        )

    def authenticate(
        self,
        auth_header: str,
        method: str,
        path: str,
        body: str = ''
    ) -> Optional[Client]:
        """
        Authenticate a request using HMAC signature.

        Validates:
        1. Header format (parses client_id, timestamp, nonce, signature)
        2. Timestamp within tolerance window
        3. Nonce not previously seen (replay protection)
        4. Signature matches expected value

        Args:
            auth_header: Authorization header value (e.g., "HMAC client_id=...,timestamp=...")
            method: HTTP method (GET, POST, etc.)
            path: Request path (e.g., "/api/users")
            body: Request body as string (empty for GET requests)

        Returns:
            Client object if authentication succeeds, None otherwise
        """
        if not auth_header:
            return None

        try:
            # Parse the authorization header
            auth_request = AuthHeaderParser.parse(auth_header)
            if not auth_request:
                return None

            # Validate signature, timestamp, and replay protection
            is_valid = self.authenticator.authenticate(
                auth_request=auth_request,
                method=method,
                path=path,
                body=body
            )

            if not is_valid:
                return None

            # Return the Client stashed by get_secret during signature
            # verification — same object whose shared_secret validated the
            # signature. This avoids a second DB lookup and closes the TOCTOU
            # window in which a legacy_key_id could be reassigned between the
            # two lookups. The take_last_resolved fallback to a fresh lookup
            # is purely defensive; on the happy path it is never reached.
            resolved = self.secret_provider.take_last_resolved(auth_request.client_id)
            if resolved is not None:
                return resolved
            return _resolve_client(self.db, auth_request.client_id)

        except Exception:
            # Real auth failures (bad signature, expired timestamp, replay)
            # return False from authenticator.authenticate rather than raising.
            # Any exception reaching here is a bug in the verification stack
            # (byteforge lib, storage backend, or our own code). Log with
            # traceback so a silent swallow can't hide it — the byteforge_hmac
            # 0.1.2 ReplayProtector crash ate 24h of traffic in exactly this
            # gap when this clause returned None with no output.
            logger.warning(
                "HMACHandler.authenticate raised — treating as auth failure",
                exc_info=True
            )
            return None

    def get_client_id_from_header(self, auth_header: str) -> Optional[str]:
        """
        Extract client ID from authorization header without validating signature.

        Useful for logging/debugging purposes.

        Args:
            auth_header: Authorization header value

        Returns:
            Client ID if header can be parsed, None otherwise
        """
        if not auth_header:
            return None

        try:
            auth_request = AuthHeaderParser.parse(auth_header)
            if auth_request:
                return auth_request.client_id
        except Exception:
            pass

        return None
