"""
Request signing utility for HMAC authentication (testing and client-side usage).
"""
import time
import uuid
import hmac
import hashlib
from typing import Optional


class RequestSigner:
    """
    Client-side request signing utility for HMAC authentication.

    Generates valid HMAC-SHA256 signatures compatible with byteforge-hmac.

    Useful for:
    - Testing HMAC authentication
    - Building client SDKs
    - Example code for API consumers

    Signature format matches byteforge-hmac:
    Message: {METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{BODY}
    Header: HMAC client_id="id",timestamp="epoch",nonce="uuid",signature="hex"
    """

    def __init__(self, client_id: str, secret_key: str):
        """
        Initialize the request signer.

        Args:
            client_id: Client identifier
            secret_key: Shared secret for HMAC signing
        """
        self.client_id = client_id
        self.secret_key = secret_key

    def sign_request(
        self,
        method: str,
        path: str,
        body: Optional[str] = None
    ) -> str:
        """
        Generate HMAC authorization header for a request.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (e.g., "/api/users")
            body: Optional request body (for POST/PUT requests)

        Returns:
            Authorization header value in HMAC format
        """
        # Generate timestamp and nonce
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())

        # Construct message to sign: {METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{BODY}
        message_parts = [
            method.upper(),
            path,
            timestamp,
            nonce,
            body if body else ''
        ]
        message = '\n'.join(message_parts)

        # Compute HMAC-SHA256 signature
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Format: HMAC client_id="id",timestamp="epoch",nonce="uuid",signature="hex"
        auth_header = f'HMAC client_id="{self.client_id}",timestamp="{timestamp}",nonce="{nonce}",signature="{signature}"'

        return auth_header

    def sign_get(self, path: str) -> str:
        """
        Sign a GET request.

        Args:
            path: Request path

        Returns:
            Authorization header value
        """
        return self.sign_request('GET', path)

    def sign_post(self, path: str, body: str) -> str:
        """
        Sign a POST request.

        Args:
            path: Request path
            body: Request body

        Returns:
            Authorization header value
        """
        return self.sign_request('POST', path, body)

    def sign_put(self, path: str, body: str) -> str:
        """
        Sign a PUT request.

        Args:
            path: Request path
            body: Request body

        Returns:
            Authorization header value
        """
        return self.sign_request('PUT', path, body)

    def sign_delete(self, path: str) -> str:
        """
        Sign a DELETE request.

        Args:
            path: Request path

        Returns:
            Authorization header value
        """
        return self.sign_request('DELETE', path)
