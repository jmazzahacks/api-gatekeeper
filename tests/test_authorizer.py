"""
Unit tests for the Authorization Engine.
CRITICAL: All tests use the api_auth_admin_test database via fixtures.
"""
import pytest
from src.auth import Authorizer, AuthResult, RequestSigner
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType
from src.models.client import Client, ClientStatus
from src.models.client_permission import ClientPermission


class TestRouteMatching:
    """Test route matching logic."""

    def test_exact_match(self, clean_db):
        """Test exact route match."""
        # Create route
        route = Route.create_new(
            route_pattern='/api/users',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/users', HttpMethod.GET)

        assert result.allowed is True
        assert result.reason == "no_auth_required"
        assert result.matched_route_id == route.route_id

    def test_wildcard_match(self, clean_db):
        """Test wildcard route match."""
        route = Route.create_new(
            route_pattern='/api/users/*',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/users/123', HttpMethod.GET)

        assert result.allowed is True
        assert result.reason == "no_auth_required"
        assert result.matched_route_id == route.route_id

    def test_no_route_match(self, clean_db):
        """Test request with no matching route."""
        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/unknown', HttpMethod.GET)

        assert result.allowed is False
        assert result.reason == "no_route_match"
        assert result.matched_route_id is None

    def test_exact_match_priority_over_wildcard(self, clean_db):
        """Test that exact match takes priority over wildcard."""
        # Create wildcard route
        wildcard_route = Route.create_new(
            route_pattern='/api/users/*',
            domain='*',
            service_name='wildcard-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(wildcard_route)

        # Create exact route
        exact_route = Route.create_new(
            route_pattern='/api/users/123',
            domain='*',
            service_name='exact-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(exact_route)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/users/123', HttpMethod.GET)

        assert result.allowed is True
        assert result.matched_route_id == exact_route.route_id

    def test_most_specific_wildcard_match(self, clean_db):
        """Test that most specific wildcard (longest prefix) is chosen."""
        # Create broad wildcard
        broad_route = Route.create_new(
            route_pattern='/api/*',
            domain='*',
            service_name='broad-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(broad_route)

        # Create specific wildcard
        specific_route = Route.create_new(
            route_pattern='/api/users/*',
            domain='*',
            service_name='specific-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(specific_route)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/users/123', HttpMethod.GET)

        assert result.allowed is True
        assert result.matched_route_id == specific_route.route_id


class TestPublicRoutes:
    """Test public routes (no authentication required)."""

    def test_public_get_request(self, clean_db):
        """Test public GET request allows access without credentials."""
        route = Route.create_new(
            route_pattern='/api/public',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/public', HttpMethod.GET)

        assert result.allowed is True
        assert result.reason == "no_auth_required"
        assert result.client_id is None

    def test_method_not_configured(self, clean_db):
        """Test request to method not configured for route."""
        route = Route.create_new(
            route_pattern='/api/test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        authorizer = Authorizer(clean_db)
        # Request POST which is not configured
        result = authorizer.authorize_request('/api/test', HttpMethod.POST)

        assert result.allowed is False
        assert result.reason == "method_not_configured"

    def test_mixed_public_protected_methods(self, clean_db):
        """Test route with both public and protected methods."""
        route = Route.create_new(
            route_pattern='/api/mixed',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
            }
        )
        clean_db.save_route(route)

        authorizer = Authorizer(clean_db)

        # GET should be public
        get_result = authorizer.authorize_request('/api/mixed', HttpMethod.GET)
        assert get_result.allowed is True
        assert get_result.reason == "no_auth_required"

        # POST should require auth
        post_result = authorizer.authorize_request('/api/mixed', HttpMethod.POST)
        assert post_result.allowed is False
        assert post_result.reason == "invalid_credentials"


class TestAuthenticatedAccess:
    """Test authenticated access with valid credentials."""

    @pytest.fixture
    def protected_route(self, clean_db):
        """Create a protected route."""
        route = Route.create_new(
            route_pattern='/api/protected',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
            }
        )
        clean_db.save_route(route)
        return route

    @pytest.fixture
    def test_client(self, clean_db):
        """Create a test client with API key."""
        client = Client.create_new(
            client_name='Test Client',
            api_key='test-api-key-123',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)
        return client

    def test_valid_api_key_with_permission(self, clean_db, protected_route, test_client):
        """Test valid API key with proper permissions allows access."""
        # Grant permission
        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=protected_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/protected',
            HttpMethod.GET,
            headers={'Authorization': 'Bearer test-api-key-123'}
        )

        assert result.allowed is True
        assert result.reason == "authenticated"
        assert result.client_id == test_client.client_id
        assert result.client_name == test_client.client_name

    def test_valid_api_key_without_permission(self, clean_db, protected_route, test_client):
        """Test valid API key without permission denies access."""
        # No permission granted

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/protected',
            HttpMethod.GET,
            headers={'Authorization': 'Bearer test-api-key-123'}
        )

        assert result.allowed is False
        assert result.reason == "no_permission"
        assert result.client_id == test_client.client_id

    def test_invalid_api_key(self, clean_db, protected_route):
        """Test invalid API key denies access."""
        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/protected',
            HttpMethod.GET,
            headers={'Authorization': 'Bearer invalid-key'}
        )

        assert result.allowed is False
        assert result.reason == "invalid_credentials"

    def test_no_credentials_for_protected_route(self, clean_db, protected_route):
        """Test no credentials for protected route denies access."""
        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request('/api/protected', HttpMethod.GET)

        assert result.allowed is False
        assert result.reason == "invalid_credentials"

    def test_valid_credentials_wrong_method(self, clean_db, protected_route, test_client):
        """Test valid credentials but wrong HTTP method denies access."""
        # Grant GET permission only
        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=protected_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        authorizer = Authorizer(clean_db)
        # Try POST which is not allowed
        result = authorizer.authorize_request(
            '/api/protected',
            HttpMethod.POST,
            headers={'Authorization': 'Bearer test-api-key-123'}
        )

        assert result.allowed is False
        assert result.reason == "method_not_allowed"
        assert result.client_id == test_client.client_id


class TestClientStatus:
    """Test client status checking (active, suspended, revoked)."""

    @pytest.fixture
    def protected_route(self, clean_db):
        """Create a protected route."""
        route = Route.create_new(
            route_pattern='/api/status-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)
        return route

    def test_suspended_client_denied(self, clean_db, protected_route):
        """Test suspended client is denied access."""
        client = Client.create_new(
            client_name='Suspended Client',
            api_key='suspended-key',
            status=ClientStatus.SUSPENDED
        )
        clean_db.save_client(client)

        # Grant permission (but client is suspended)
        permission = ClientPermission.create_new(
            client_id=client.client_id,
            route_id=protected_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/status-test',
            HttpMethod.GET,
            headers={'Authorization': 'Bearer suspended-key'}
        )

        assert result.allowed is False
        assert result.reason == "client_suspended"
        assert result.client_id == client.client_id

    def test_revoked_client_denied(self, clean_db, protected_route):
        """Test revoked client is denied access."""
        client = Client.create_new(
            client_name='Revoked Client',
            api_key='revoked-key',
            status=ClientStatus.REVOKED
        )
        clean_db.save_client(client)

        permission = ClientPermission.create_new(
            client_id=client.client_id,
            route_id=protected_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/status-test',
            HttpMethod.GET,
            headers={'Authorization': 'Bearer revoked-key'}
        )

        assert result.allowed is False
        assert result.reason == "client_revoked"
        assert result.client_id == client.client_id

    def test_active_client_allowed(self, clean_db, protected_route):
        """Test active client with permissions is allowed."""
        client = Client.create_new(
            client_name='Active Client',
            api_key='active-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)

        permission = ClientPermission.create_new(
            client_id=client.client_id,
            route_id=protected_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/status-test',
            HttpMethod.GET,
            headers={'Authorization': 'Bearer active-key'}
        )

        assert result.allowed is True
        assert result.reason == "authenticated"


class TestSharedSecretAuth:
    """Test HMAC/shared secret authentication."""

    def test_valid_shared_secret_with_permission(self, clean_db):
        """Test valid shared secret with permission allows access."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/hmac-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        clean_db.save_route(route)

        # Create client with shared secret
        client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='test-shared-secret',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)

        # Grant permission
        permission = ClientPermission.create_new(
            client_id=client.client_id,
            route_id=route.route_id,
            allowed_methods=[HttpMethod.POST]
        )
        clean_db.save_permission(permission)

        # Sign the request using RequestSigner
        signer = RequestSigner(
            client_id=client.client_id,
            secret_key='test-shared-secret'
        )
        auth_header = signer.sign_post('/api/hmac-test', '{"test": "data"}')

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/hmac-test',
            HttpMethod.POST,
            headers={'Authorization': auth_header},
            body='{"test": "data"}'
        )

        assert result.allowed is True
        assert result.reason == "authenticated"
        assert result.client_id == client.client_id

    def test_invalid_shared_secret(self, clean_db):
        """Test invalid shared secret denies access."""
        route = Route.create_new(
            route_pattern='/api/hmac-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        clean_db.save_route(route)

        # Sign with wrong secret
        signer = RequestSigner(
            client_id='fake-client-id',
            secret_key='wrong-secret'
        )
        auth_header = signer.sign_post('/api/hmac-test', '{"test": "data"}')

        authorizer = Authorizer(clean_db)
        result = authorizer.authorize_request(
            '/api/hmac-test',
            HttpMethod.POST,
            headers={'Authorization': auth_header},
            body='{"test": "data"}'
        )

        assert result.allowed is False
        assert result.reason == "invalid_credentials"


class TestAuthResultModel:
    """Test AuthResult model methods."""

    def test_to_dict(self):
        """Test AuthResult to_dict method."""
        result = AuthResult(
            allowed=True,
            reason="authenticated",
            client_id="client-123",
            client_name="Test Client",
            matched_route_id="route-456"
        )

        data = result.to_dict()

        assert data['allowed'] is True
        assert data['reason'] == "authenticated"
        assert data['client_id'] == "client-123"
        assert data['client_name'] == "Test Client"
        assert data['matched_route_id'] == "route-456"

    def test_from_dict(self):
        """Test AuthResult from_dict method."""
        data = {
            'allowed': False,
            'reason': "no_permission",
            'client_id': "client-789",
            'client_name': "Denied Client",
            'matched_route_id': "route-abc"
        }

        result = AuthResult.from_dict(data)

        assert result.allowed is False
        assert result.reason == "no_permission"
        assert result.client_id == "client-789"
        assert result.client_name == "Denied Client"
        assert result.matched_route_id == "route-abc"

    def test_from_dict_optional_fields(self):
        """Test AuthResult from_dict with optional fields missing."""
        data = {
            'allowed': True,
            'reason': "no_auth_required"
        }

        result = AuthResult.from_dict(data)

        assert result.allowed is True
        assert result.reason == "no_auth_required"
        assert result.client_id is None
        assert result.client_name is None
        assert result.matched_route_id is None
