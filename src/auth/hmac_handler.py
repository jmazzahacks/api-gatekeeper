"""
HMAC authentication handler using byteforge-hmac library.
"""
from typing import Optional, Dict
from byteforge_hmac import (
    HMACAuthenticator,
    AuthHeaderParser,
    SecretProvider
)

from src.database.driver import AuthServiceDB
from src.models.client import Client


class DatabaseSecretProvider(SecretProvider):
    """
    Secret provider that fetches client secrets from database.

    Integrates byteforge-hmac with our database layer.
    """

    def __init__(self, db: AuthServiceDB):
        """
        Initialize the secret provider.

        Args:
            db: Database driver instance
        """
        self.db = db

    def get_secret(self, client_id: str) -> Optional[str]:
        """
        Get the shared secret for a client.

        Args:
            client_id: Client identifier

        Returns:
            Shared secret if client exists and has one, None otherwise
        """
        client = self.db.load_client_by_id(client_id)
        if client and client.shared_secret:
            return client.shared_secret
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

            # Authentication succeeded - load and return the client
            client = self.db.load_client_by_id(auth_request.client_id)
            return client

        except Exception:
            # Authentication failed (invalid format, expired timestamp, replay, etc.)
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
