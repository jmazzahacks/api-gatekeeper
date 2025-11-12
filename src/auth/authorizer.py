"""
Authorization engine for API Gatekeeper.
"""
from typing import Optional, List, Dict
from src.database.driver import AuthServiceDB
from src.models.route import Route, HttpMethod
from src.models.client import Client
from .models import AuthResult
from .hmac_handler import HMACHandler
from .api_key_handler import APIKeyHandler


class Authorizer:
    """
    Main authorization engine.

    Handles the complete authorization flow:
    1. Match request path to configured routes
    2. Check if authentication is required for the HTTP method
    3. If required, validate credentials and authenticate client
    4. Check client status (active/suspended/revoked)
    5. Verify client has permission for the route and method
    6. Return authorization decision with context
    """

    def __init__(
        self,
        db: AuthServiceDB,
        hmac_handler: Optional[HMACHandler] = None,
        api_key_handler: Optional[APIKeyHandler] = None
    ):
        """
        Initialize the authorizer.

        Args:
            db: Database driver instance
            hmac_handler: Optional HMAC authentication handler (created if not provided)
            api_key_handler: Optional API key handler (created if not provided)
        """
        self.db = db
        self.hmac_handler = hmac_handler or HMACHandler(db)
        self.api_key_handler = api_key_handler or APIKeyHandler()

    def authorize_request(
        self,
        path: str,
        method: HttpMethod,
        domain: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: str = '',
        query_params: Optional[Dict[str, str]] = None
    ) -> AuthResult:
        """
        Determine if a request should be allowed.

        Args:
            path: Request path (e.g., '/api/users/123')
            method: HTTP method
            domain: Domain for route matching (optional, e.g., 'api.example.com')
            headers: HTTP headers dict (for extracting auth credentials)
            body: Request body (for HMAC signature validation)
            query_params: Query parameters (for API key extraction)

        Returns:
            AuthResult with decision and context
        """
        if headers is None:
            headers = {}
        if query_params is None:
            query_params = {}
        # Step 1: Match routes
        matching_routes = self._match_routes(path, domain)

        if not matching_routes:
            return AuthResult(
                allowed=False,
                reason="no_route_match"
            )

        # Step 2: Select best matching route (exact over wildcard)
        route = self._select_best_route(matching_routes, path)

        # Step 3: Check if authentication is required for this method
        method_auth = route.get_auth_requirements(method)

        if not method_auth:
            # Method not configured for this route
            return AuthResult(
                allowed=False,
                reason="method_not_configured",
                matched_route_id=route.route_id
            )

        if not method_auth.auth_required:
            # Public route - no authentication needed
            return AuthResult(
                allowed=True,
                reason="no_auth_required",
                matched_route_id=route.route_id
            )

        # Step 4: Authentication required - validate credentials
        client = self._authenticate_client(headers, path, method.value, body, query_params)

        if not client:
            return AuthResult(
                allowed=False,
                reason="invalid_credentials",
                matched_route_id=route.route_id
            )

        # Step 5: Check client status
        if not client.is_active():
            return AuthResult(
                allowed=False,
                reason=f"client_{client.status.value}",
                client_id=client.client_id,
                client_name=client.client_name,
                matched_route_id=route.route_id
            )

        # Step 6: Check permissions
        return self._check_permission(client, route, method)

    def _match_routes(self, path: str, domain: Optional[str] = None) -> List[Route]:
        """
        Find all routes that match the given path and domain.

        Matches both exact routes and wildcard routes.
        Matches exact domains, wildcard domains (*.example.com), and any domain (*).

        Args:
            path: Request path
            domain: Domain for route matching (optional)

        Returns:
            List of matching routes sorted by specificity (may be empty)
        """
        return self.db.find_matching_routes(path, domain)

    def _select_best_route(self, routes: List[Route], path: str) -> Route:
        """
        Select the best matching route from multiple matches.

        Priority:
        1. Exact match over wildcard
        2. If multiple wildcards, choose longest prefix (most specific)

        Args:
            routes: List of matching routes
            path: Request path

        Returns:
            Best matching route
        """
        if len(routes) == 1:
            return routes[0]

        # Separate exact and wildcard matches
        exact_matches = [r for r in routes if not r.route_pattern.endswith('/*')]
        wildcard_matches = [r for r in routes if r.route_pattern.endswith('/*')]

        # Exact match takes priority
        if exact_matches:
            if len(exact_matches) > 1:
                # Should not happen with unique patterns, but handle gracefully
                # Return first one
                return exact_matches[0]
            return exact_matches[0]

        # Multiple wildcard matches - choose longest prefix (most specific)
        if wildcard_matches:
            # Sort by pattern length descending (longer = more specific)
            wildcard_matches.sort(key=lambda r: len(r.route_pattern), reverse=True)
            return wildcard_matches[0]

        # Fallback (shouldn't reach here)
        return routes[0]

    def _authenticate_client(
        self,
        headers: Dict[str, str],
        path: str,
        method: str,
        body: str,
        query_params: Dict[str, str]
    ) -> Optional[Client]:
        """
        Authenticate a client using credentials from request.

        Tries authentication in order:
        1. HMAC signature (from Authorization header)
        2. API key (from Authorization header or query params)

        Args:
            headers: HTTP headers
            path: Request path
            method: HTTP method string
            body: Request body
            query_params: Query parameters

        Returns:
            Client if authenticated, None otherwise
        """
        # Try HMAC authentication first (more secure)
        auth_header = headers.get('Authorization', '')
        if auth_header and auth_header.startswith('HMAC '):
            client = self.hmac_handler.authenticate(
                auth_header=auth_header,
                method=method,
                path=path,
                body=body
            )
            if client:
                return client

        # Try API key authentication
        api_key = self.api_key_handler.extract(headers, query_params)
        if api_key:
            client = self.db.load_client_by_api_key(api_key)
            if client:
                return client

        return None

    def _check_permission(
        self,
        client: Client,
        route: Route,
        method: HttpMethod
    ) -> AuthResult:
        """
        Check if a client has permission to access a route with a specific method.

        Args:
            client: Authenticated client
            route: Matched route
            method: HTTP method

        Returns:
            AuthResult with permission decision
        """
        # Load permission for this client and route
        permission = self.db.load_permission_by_client_and_route(
            client.client_id,
            route.route_id
        )

        if not permission:
            return AuthResult(
                allowed=False,
                reason="no_permission",
                client_id=client.client_id,
                client_name=client.client_name,
                matched_route_id=route.route_id
            )

        if not permission.allows_method(method):
            return AuthResult(
                allowed=False,
                reason="method_not_allowed",
                client_id=client.client_id,
                client_name=client.client_name,
                matched_route_id=route.route_id
            )

        return AuthResult(
            allowed=True,
            reason="authenticated",
            client_id=client.client_id,
            client_name=client.client_name,
            matched_route_id=route.route_id
        )
