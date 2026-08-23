"""
Unit tests for Flask application endpoints.

Tests the /authz and /health endpoints using Flask test client.
Mocks nginx headers (X-Original-URI, X-Original-Method) to simulate
nginx auth_request integration.
"""
import pytest
from src.app import create_app
from api_gatekeeper_models import Route, HttpMethod, MethodAuth, AuthType, Client, ClientStatus, ClientPermission
from src.auth import RequestSigner, HMACHandler


@pytest.fixture
def client(clean_db):
    """Flask test client with test database."""
    # Use in-memory nonce storage for tests (no Redis dependency)
    # Explicitly pass redis_client=None to avoid connecting to real Redis
    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def cors_client(clean_db):
    """Flask test client with a CORS allowlist configured."""
    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    app.config['CORS_ALLOWED_ORIGINS'] = frozenset({'https://allowed.example.com'})
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
        assert data['redis'] == 'not_configured'  # No Redis in test fixture
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

    def test_health_check_with_redis(self, clean_db):
        """Test health check reports Redis status when configured."""
        from unittest.mock import Mock

        # Create mock Redis client
        mock_redis = Mock()
        mock_redis.ping.return_value = True

        hmac_handler = HMACHandler(clean_db, nonce_storage={})
        app = create_app(db=clean_db, redis_client=mock_redis, hmac_handler=hmac_handler, rate_limiter=None)
        app.config['TESTING'] = True

        with app.test_client() as test_client:
            response = test_client.get('/health')

            assert response.status_code == 200
            data = response.get_json()
            assert data['status'] == 'healthy'
            assert data['redis'] == 'connected'
            mock_redis.ping.assert_called_once()

    def test_health_check_redis_failure(self, clean_db):
        """Test health check returns 503 when Redis connection fails."""
        from unittest.mock import Mock
        import redis

        # Create mock Redis client that fails ping
        mock_redis = Mock()
        mock_redis.ping.side_effect = redis.ConnectionError("Connection refused")

        hmac_handler = HMACHandler(clean_db, nonce_storage={})
        app = create_app(db=clean_db, redis_client=mock_redis, hmac_handler=hmac_handler, rate_limiter=None)
        app.config['TESTING'] = True

        with app.test_client() as test_client:
            response = test_client.get('/health')

            assert response.status_code == 503
            data = response.get_json()
            assert data['status'] == 'unhealthy'
            assert data['database'] == 'connected'
            assert data['redis'] == 'error'
            assert data['message'] == 'Redis connection failed'


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


class TestAuthzEndpointCorsPreflight:
    """Test /authz endpoint OPTIONS preflight short-circuit."""

    def _make_route(self, clean_db, pattern='/api/cors-test'):
        route = Route.create_new(
            route_pattern=pattern,
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
                HttpMethod.GET: MethodAuth(auth_required=False),
            },
        )
        clean_db.save_route(route)
        return route

    def test_preflight_allowed_origin_returns_cors_headers(self, cors_client, clean_db):
        self._make_route(clean_db)
        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type, Authorization',
            },
        )

        assert response.status_code == 200
        assert response.headers['Access-Control-Allow-Origin'] == 'https://allowed.example.com'
        # Allow-Methods reflects the route's configured methods + OPTIONS
        allow_methods = {m.strip() for m in response.headers['Access-Control-Allow-Methods'].split(',')}
        assert allow_methods == {'GET', 'POST', 'OPTIONS'}
        assert response.headers['Access-Control-Allow-Headers'] == 'Content-Type, Authorization'
        assert response.headers['Access-Control-Max-Age'] == '86400'
        assert response.headers['Vary'] == 'Origin'

    def test_preflight_disallowed_origin_returns_403(self, cors_client, clean_db):
        self._make_route(clean_db)
        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://evil.example.com',
                'Access-Control-Request-Method': 'POST',
            },
        )

        assert response.status_code == 403
        assert b'cors_origin_not_allowed' in response.data
        assert 'Access-Control-Allow-Origin' not in response.headers

    def test_preflight_unknown_route_returns_403(self, cors_client, clean_db):
        # No route configured for this path
        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/does-not-exist',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                'Access-Control-Request-Method': 'POST',
            },
        )

        assert response.status_code == 403
        assert b'no_route_match' in response.data

    def test_preflight_default_request_headers_when_absent(self, cors_client, clean_db):
        self._make_route(clean_db)
        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                'Access-Control-Request-Method': 'POST',
                # no Access-Control-Request-Headers
            },
        )

        assert response.status_code == 200
        assert response.headers['Access-Control-Allow-Headers'] == 'Content-Type, Authorization'

    def test_preflight_without_allowlist_denies(self, client, clean_db):
        # Default `client` fixture has no CORS allowlist — preflights are denied.
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=False)},
        )
        clean_db.save_route(route)

        response = client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                'Access-Control-Request-Method': 'POST',
            },
        )

        assert response.status_code == 403
        assert b'cors_origin_not_allowed' in response.data

    def test_actual_response_carries_cors_headers_when_allowed(self, cors_client, clean_db):
        # Public route + actual GET from an allowed origin -> 200 with Allow-Origin/Vary
        route = Route.create_new(
            route_pattern='/api/cors-public',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-public',
                'X-Original-Method': 'GET',
                'X-Original-Origin': 'https://allowed.example.com',
            },
        )

        assert response.status_code == 200
        assert response.headers['Access-Control-Allow-Origin'] == 'https://allowed.example.com'
        assert response.headers['Vary'] == 'Origin'

    def test_actual_response_omits_cors_headers_for_disallowed_origin(self, cors_client, clean_db):
        route = Route.create_new(
            route_pattern='/api/cors-public',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-public',
                'X-Original-Method': 'GET',
                'X-Original-Origin': 'https://evil.example.com',
            },
        )

        assert response.status_code == 200
        assert 'Access-Control-Allow-Origin' not in response.headers

    def test_denial_response_carries_cors_headers_when_allowed(self, cors_client, clean_db):
        # Auth required route, no credentials -> 403, but with CORS headers so the
        # browser can actually read the denial reason.
        route = Route.create_new(
            route_pattern='/api/cors-protected',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)},
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-protected',
                'X-Original-Method': 'GET',
                'X-Original-Origin': 'https://allowed.example.com',
            },
        )

        assert response.status_code == 403
        assert response.headers['Access-Control-Allow-Origin'] == 'https://allowed.example.com'
        assert response.headers['Vary'] == 'Origin'

    def test_bare_options_no_origin_falls_through_to_method_policy(self, cors_client, clean_db):
        # A CORS preflight always carries both Origin and
        # Access-Control-Request-Method. An OPTIONS with neither is a
        # non-browser caller (curl, health probe) and must be evaluated
        # against the route's method policy — not silently denied by the
        # CORS allowlist gate.
        # Regression for ticket 3fb82016 (2026-08-19).
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.OPTIONS: MethodAuth(auth_required=False),
            },
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                # no X-Original-Origin, no Access-Control-Request-Method
            },
        )

        assert response.status_code == 200
        assert response.data == b''

    def test_bare_options_no_options_in_method_policy_denies(self, cors_client, clean_db):
        # Same shape as above but the route has NO OPTIONS entry. Falls
        # through to method-policy which returns method_not_configured.
        # Confirms the fall-through path routes to the authorizer instead
        # of being caught by the CORS branch.
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
                HttpMethod.GET: MethodAuth(auth_required=False),
            },
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
            },
        )

        assert response.status_code == 403
        # Assert the reason positively — the bug was specifically
        # cors_origin_not_allowed coming back here, and a bare
        # `not in response.data` would also pass on an empty body.
        assert response.data == b'method_not_configured'

    def test_bare_options_on_protected_route_requires_credentials(self, cors_client, clean_db):
        # The auth boundary on the new fall-through path: a route whose
        # OPTIONS entry requires auth must still deny an uncredentialed
        # bare OPTIONS. Moving OPTIONS onto the authorizer path must not
        # mean OPTIONS skips authentication.
        route = Route.create_new(
            route_pattern='/api/cors-guarded',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.OPTIONS: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
            },
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-guarded',
                'X-Original-Method': 'OPTIONS',
            },
        )

        assert response.status_code == 403
        assert response.data == b'invalid_credentials'

    def test_bare_options_on_protected_route_allows_valid_credentials(self, cors_client, clean_db):
        # Converse of the above: with a valid key and an OPTIONS grant, the
        # bare OPTIONS is authorized like any other method.
        route = Route.create_new(
            route_pattern='/api/cors-guarded',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.OPTIONS: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
            },
        )
        clean_db.save_route(route)

        test_client = Client.create_new(
            client_name='Options Client',
            api_key='options-key-123',
            status=ClientStatus.ACTIVE,
        )
        clean_db.save_client(test_client)

        permission = ClientPermission.create_new(
            client_id=test_client.client_id,
            route_id=route.route_id,
            allowed_methods=[HttpMethod.OPTIONS],
        )
        clean_db.save_permission(permission)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-guarded',
                'X-Original-Method': 'OPTIONS',
                'Authorization': 'Bearer options-key-123',
            },
        )

        assert response.status_code == 200
        assert response.headers['X-Auth-Client-ID'] == test_client.client_id

    def test_preflight_for_unconfigured_method_denied(self, cors_client, clean_db):
        # A preflight only gets a 200 for a method the route actually
        # configures. Without this the preflight branch answered "yes" for
        # any Access-Control-Request-Method on any matched route, since it
        # never consults the method policy — so an allowlisted origin could
        # get an unauthenticated OPTIONS proxied upstream for a method the
        # route does not expose at all.
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                'Access-Control-Request-Method': 'DELETE',
            },
        )

        assert response.status_code == 403
        assert response.data == b'method_not_configured'
        assert 'Access-Control-Allow-Origin' not in response.headers

    def test_preflight_for_unknown_method_denied(self, cors_client, clean_db):
        # Access-Control-Request-Method naming something outside HttpMethod
        # must not raise — it's a denial, same as an unconfigured method.
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                'Access-Control-Request-Method': 'PROPFIND',
            },
        )

        assert response.status_code == 403
        assert response.data == b'method_not_configured'

    def test_preflight_origin_gate_precedes_method_gate(self, cors_client, clean_db):
        # Ordering matters for information disclosure: a non-allowlisted
        # origin must be turned away before it can probe which methods a
        # route exposes.
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://evil.example.com',
                'Access-Control-Request-Method': 'DELETE',
            },
        )

        assert response.status_code == 403
        assert response.data == b'cors_origin_not_allowed'

    def test_options_with_origin_but_no_acrm_falls_through(self, cors_client, clean_db):
        # Origin present but Access-Control-Request-Method missing is not a
        # preflight per spec (missing the "what method am I about to send?"
        # signal). Treat as ordinary OPTIONS and defer to method policy.
        route = Route.create_new(
            route_pattern='/api/cors-test',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.OPTIONS: MethodAuth(auth_required=False),
            },
        )
        clean_db.save_route(route)

        response = cors_client.get(
            '/authz',
            headers={
                'X-Original-URI': '/api/cors-test',
                'X-Original-Method': 'OPTIONS',
                'X-Original-Origin': 'https://allowed.example.com',
                # no Access-Control-Request-Method
            },
        )

        assert response.status_code == 200
        # Not a preflight, so the CORS-specific Allow-Methods / Max-Age
        # headers should NOT be stamped by _handle_cors_preflight.
        assert 'Access-Control-Allow-Methods' not in response.headers
        assert 'Access-Control-Max-Age' not in response.headers


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
