"""
API key authentication handler.
"""
from typing import Optional


class APIKeyHandler:
    """
    Handler for API key extraction and validation.

    Supports extracting API keys from:
    - Authorization header (Bearer or ApiKey format)
    - Query parameters
    """

    def __init__(
        self,
        header_name: str = "Authorization",
        query_param_name: str = "api_key"
    ):
        """
        Initialize the API key handler.

        Args:
            header_name: Name of the header to check (default: "Authorization")
            query_param_name: Name of query parameter to check (default: "api_key")
        """
        self.header_name = header_name
        self.query_param_name = query_param_name

    def extract_from_header(self, headers: dict) -> Optional[str]:
        """
        Extract API key from Authorization header.

        Supports formats:
        - "Bearer <api_key>"
        - "ApiKey <api_key>"
        - "<api_key>" (raw key)

        Args:
            headers: Dictionary of HTTP headers (case-insensitive keys)

        Returns:
            API key if found, None otherwise
        """
        # Get authorization header (case-insensitive)
        auth_header = None
        for key, value in headers.items():
            if key.lower() == self.header_name.lower():
                auth_header = value
                break

        if not auth_header:
            return None

        auth_header = auth_header.strip()

        # Check for "Bearer <key>" format
        if auth_header.lower().startswith('bearer '):
            return auth_header[7:].strip()

        # Check for "ApiKey <key>" format
        if auth_header.lower().startswith('apikey '):
            return auth_header[7:].strip()

        # Assume it's a raw API key (no prefix)
        # But skip if it looks like HMAC format
        if auth_header.lower().startswith('hmac '):
            return None

        return auth_header

    def extract_from_query(self, query_params: dict) -> Optional[str]:
        """
        Extract API key from query parameters.

        Args:
            query_params: Dictionary of query parameters

        Returns:
            API key if found, None otherwise
        """
        if not query_params:
            return None

        # Case-insensitive lookup
        for key, value in query_params.items():
            if key.lower() == self.query_param_name.lower():
                if isinstance(value, list):
                    # Handle multiple values (take first)
                    return value[0] if value else None
                return value

        return None

    def extract(self, headers: dict, query_params: Optional[dict] = None) -> Optional[str]:
        """
        Extract API key from headers or query parameters.

        Priority: Header takes precedence over query parameter.

        Args:
            headers: Dictionary of HTTP headers
            query_params: Optional dictionary of query parameters

        Returns:
            API key if found, None otherwise
        """
        # Try header first
        api_key = self.extract_from_header(headers)
        if api_key:
            return api_key

        # Fall back to query parameter
        if query_params:
            return self.extract_from_query(query_params)

        return None
