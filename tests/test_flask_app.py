"""
Unit tests for Flask application endpoints.

Tests the /authz and /health endpoints using Flask test client.
Mocks nginx headers (X-Original-URI, X-Original-Method) to simulate
nginx auth_request integration.
"""
import pytest
from src.app import create_app
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType
from src.models.client import Client, ClientStatus
from src.models.client_permission import ClientPermission
from src.auth import RequestSigner, HMACHandler


@pytest.fixture
def client(clean_db):
    """Flask test client with test database."""
    # Use in-memory nonce storage for tests (no Redis dependency)
    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestHealthEndpoint:
    """Test /health endpoint."""

    def test_health_check_success(self, client, clean_db):
        """Test health check returns 200 when database is connected."""
        response = client.get('/health')

        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert data['database'] == 'connected'
        assert 'routes_configured' in data
        assert 'clients_configured' in data
        assert isinstance(data['routes_configured'], int)
        assert isinstance(data['clients_configured'], int)

    def test_health_check_with_existing_data(self, client, clean_db):
        """Test health check reports correct counts."""
        # Create some routes and clients
        route1 = Route.create_new(
            route_pattern='/api/test1',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route2 = Route.create_new(
            route_pattern='/api/test2',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route1)
        clean_db.save_route(route2)

        test_client = Client.create_new(
            client_name='Test Client',
            api_key='test-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        response = client.get('/health')

        assert response.status_code == 200
        data = response.get_json()
        assert data['routes_configured'] == 2
        assert data['clients_configured'] == 1


class TestAuthzEndpointPublicRoutes:
    """Test /authz endpoint with public routes (no authentication required)."""

    def test_public_route_allowed(self, client, clean_db):
        """Test public route returns 200 without credentials."""
        # Create a public route
        route = Route.create_new(
            route_pattern='/api/public',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        # Make request to authz endpoint with nginx headers
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/public',
                'X-Original-Method': 'GET'
            }
        )

        assert response.status_code == 200
        # Public routes don't set client headers
        assert 'X-Auth-Client-ID' not in response.headers

    def test_public_post_allowed(self, client, clean_db):
        """Test public POST request returns 200."""
        route = Route.create_new(
            route_pattern='/api/register',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        response = client.post(
            '/authz',
            headers={
                'X-Original-URI': '/api/register',
                'X-Original-Method': 'POST'
            },
            data='{"username": "test"}'
        )

        assert response.status_code == 200

    def test_route_not_found(self, client, clean_db):
        """Test non-existent route returns 403."""
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/nonexistent',
                'X-Original-Method': 'GET'
            }
        )

        assert response.status_code == 403
        assert b'no_route_match' in response.data


class TestAuthzEndpointAPIKey:
    """Test /authz endpoint with API key authentication."""

    def test_valid_api_key_with_permission(self, client, clean_db):
        """Test valid API key with permission returns 200 and sets client headers."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/protected',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)

        # Create client with API key
        test_client = Client.create_new(
            client_name='Test Client',
            api_key='test-api-key-123',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        # Grant permission
        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        # Make request with API key
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/protected',
                'X-Original-Method': 'GET',
                'Authorization': 'Bearer test-api-key-123'
            }
        )

        assert response.status_code == 200
        assert response.headers['X-Auth-Client-ID'] == test_client.client_id
        assert response.headers['X-Auth-Client-Name'] == 'Test Client'
        assert 'X-Auth-Route-ID' in response.headers

    def test_valid_api_key_without_permission(self, client, clean_db):
        """Test valid API key without permission returns 403."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/protected',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)

        # Create client with API key (no permission granted)
        test_client = Client.create_new(
            client_name='Test Client',
            api_key='test-api-key-123',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        # Make request with API key
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/protected',
                'X-Original-Method': 'GET',
                'Authorization': 'Bearer test-api-key-123'
            }
        )

        assert response.status_code == 403
        assert b'no_permission' in response.data

    def test_invalid_api_key(self, client, clean_db):
        """Test invalid API key returns 403."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/protected',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)

        # Make request with invalid API key
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/protected',
                'X-Original-Method': 'GET',
                'Authorization': 'Bearer invalid-key'
            }
        )

        assert response.status_code == 403
        assert b'invalid_credentials' in response.data

    def test_suspended_client_denied(self, client, clean_db):
        """Test suspended client returns 403."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/protected',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)

        # Create suspended client
        test_client = Client.create_new(
            client_name='Suspended Client',
            api_key='suspended-key',
            status=ClientStatus.SUSPENDED
        )
        clean_db.save_client(test_client)

        # Grant permission (but client is suspended)
        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        # Make request
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/protected',
                'X-Original-Method': 'GET',
                'Authorization': 'Bearer suspended-key'
            }
        )

        assert response.status_code == 403
        assert b'client_suspended' in response.data


class TestAuthzEndpointHMAC:
    """Test /authz endpoint with HMAC authentication."""

    def test_valid_hmac_signature(self, client, clean_db):
        """Test valid HMAC signature returns 200."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/hmac-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        clean_db.save_route(route)

        # Create client with shared secret
        test_client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='hmac-secret-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        # Grant permission
        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=route.route_id,
            allowed_methods=[HttpMethod.POST]
        )
        clean_db.save_permission(permission)

        # Sign request
        signer = RequestSigner(
            client_id=test_client.client_id,
            secret_key='hmac-secret-key'
        )
        body = '{"test": "data"}'
        auth_header = signer.sign_post('/api/hmac-test', body)

        # Make request with HMAC signature
        response = client.post(
            '/authz',
            headers={
                'X-Original-URI': '/api/hmac-test',
                'X-Original-Method': 'POST',
                'Authorization': auth_header
            },
            data=body
        )

        assert response.status_code == 200
        assert response.headers['X-Auth-Client-ID'] == test_client.client_id
        assert response.headers['X-Auth-Client-Name'] == 'HMAC Client'

    def test_invalid_hmac_signature(self, client, clean_db):
        """Test invalid HMAC signature returns 403."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/hmac-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        clean_db.save_route(route)

        # Create client with shared secret
        test_client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='hmac-secret-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        # Sign request with WRONG secret
        signer = RequestSigner(
            client_id=test_client.client_id,
            secret_key='wrong-secret'
        )
        body = '{"test": "data"}'
        auth_header = signer.sign_post('/api/hmac-test', body)

        # Make request
        response = client.post(
            '/authz',
            headers={
                'X-Original-URI': '/api/hmac-test',
                'X-Original-Method': 'POST',
                'Authorization': auth_header
            },
            data=body
        )

        assert response.status_code == 403
        assert b'invalid_credentials' in response.data

    def test_hmac_body_tampering_detected(self, client, clean_db):
        """Test HMAC detects body tampering."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/hmac-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        clean_db.save_route(route)

        # Create client
        test_client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='hmac-secret-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        # Sign request with original body
        signer = RequestSigner(
            client_id=test_client.client_id,
            secret_key='hmac-secret-key'
        )
        original_body = '{"test": "original"}'
        auth_header = signer.sign_post('/api/hmac-test', original_body)

        # Make request with TAMPERED body
        tampered_body = '{"test": "tampered"}'
        response = client.post(
            '/authz',
            headers={
                'X-Original-URI': '/api/hmac-test',
                'X-Original-Method': 'POST',
                'Authorization': auth_header
            },
            data=tampered_body
        )

        assert response.status_code == 403
        assert b'invalid_credentials' in response.data


class TestAuthzEndpointQueryParams:
    """Test /authz endpoint with API key in query parameters."""

    def test_api_key_from_query_param(self, client, clean_db):
        """Test API key in query parameter works."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/query-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)

        # Create client
        test_client = Client.create_new(
            client_name='Query Client',
            api_key='query-key-123',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(test_client)

        # Grant permission
        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        # Make request with API key in query string
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/query-test?api_key=query-key-123',
                'X-Original-Method': 'GET'
            }
        )

        assert response.status_code == 200
        assert response.headers['X-Auth-Client-ID'] == test_client.client_id


class TestAuthzEndpointEdgeCases:
    """Test /authz endpoint edge cases and error handling."""

    def test_missing_original_uri_header(self, client, clean_db):
        """Test missing X-Original-URI returns 400."""
        response = client.get(
            '/authz',
            headers={'X-Original-Method': 'GET'}
        )

        assert response.status_code == 400
        assert b'Missing required headers' in response.data

    def test_missing_original_method_header(self, client, clean_db):
        """Test missing X-Original-Method returns 400."""
        response = client.get(
            '/authz',
            headers={'X-Original-URI': '/api/test'}
        )

        assert response.status_code == 400
        assert b'Missing required headers' in response.data

    def test_invalid_http_method(self, client, clean_db):
        """Test invalid HTTP method returns 400."""
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/test',
                'X-Original-Method': 'INVALID'
            }
        )

        assert response.status_code == 400
        assert b'Invalid method' in response.data

    def test_protected_route_no_credentials(self, client, clean_db):
        """Test protected route without credentials returns 403."""
        # Create protected route
        route = Route.create_new(
            route_pattern='/api/protected',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route)

        # Make request without credentials
        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/protected',
                'X-Original-Method': 'GET'
            }
        )

        assert response.status_code == 403
        assert b'invalid_credentials' in response.data


class TestMetricsEndpoint:
    """Test /metrics endpoint (Prometheus metrics)."""

    def test_metrics_endpoint_returns_prometheus_format(self, client, clean_db):
        """Test /metrics returns Prometheus-formatted metrics."""
        response = client.get('/metrics')

        assert response.status_code == 200
        assert response.content_type.startswith('text/plain')

        # Check for standard Prometheus metrics
        data = response.data.decode('utf-8')
        assert '# HELP' in data
        assert '# TYPE' in data

    def test_metrics_contains_auth_metrics(self, client, clean_db):
        """Test /metrics contains our custom authorization metrics."""
        response = client.get('/metrics')

        assert response.status_code == 200
        data = response.data.decode('utf-8')

        # Check for our custom metrics
        assert 'auth_requests_total' in data
        assert 'auth_duration_seconds' in data
        assert 'auth_errors_total' in data

    def test_metrics_updates_after_authz_request(self, client, clean_db):
        """Test metrics are updated after authorization requests."""
        # Create a public route
        route = Route.create_new(
            route_pattern='/api/metrics-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        # Get initial metrics
        response1 = client.get('/metrics')
        data1 = response1.data.decode('utf-8')

        # Make an authorization request
        client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/metrics-test',
                'X-Original-Method': 'GET'
            }
        )

        # Get updated metrics
        response2 = client.get('/metrics')
        data2 = response2.data.decode('utf-8')

        # Verify metrics were updated (should contain auth_requests_total)
        assert 'auth_requests_total' in data2

        # The metrics should contain our route pattern
        assert '/api/metrics-test' in data2 or 'result="allowed"' in data2

    def test_metrics_tracks_allowed_vs_denied(self, client, clean_db):
        """Test metrics differentiate between allowed and denied requests."""
        # Create public route
        public_route = Route.create_new(
            route_pattern='/api/public-metrics',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(public_route)

        # Create protected route
        protected_route = Route.create_new(
            route_pattern='/api/protected-metrics',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(protected_route)

        # Make allowed request
        client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/public-metrics',
                'X-Original-Method': 'GET'
            }
        )

        # Make denied request
        client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/protected-metrics',
                'X-Original-Method': 'GET'
            }
        )

        # Check metrics
        response = client.get('/metrics')
        data = response.data.decode('utf-8')

        # Should have both allowed and denied counters
        assert 'result="allowed"' in data
        assert 'result="denied"' in data
