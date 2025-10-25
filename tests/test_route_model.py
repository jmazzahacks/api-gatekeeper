"""
Unit tests for Route and MethodAuth models.
Tests model validation, serialization, and business logic.
"""
import pytest
import time
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType


class TestMethodAuth:
    """Test MethodAuth model."""

    def test_create_no_auth_required(self):
        """Test creating MethodAuth with no authentication required."""
        method_auth = MethodAuth(auth_required=False)
        assert method_auth.auth_required is False
        assert method_auth.auth_type is None

    def test_create_with_api_key_auth(self):
        """Test creating MethodAuth with API key authentication."""
        method_auth = MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
        assert method_auth.auth_required is True
        assert method_auth.auth_type == AuthType.API_KEY

    def test_create_with_hmac_auth(self):
        """Test creating MethodAuth with HMAC authentication."""
        method_auth = MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
        assert method_auth.auth_required is True
        assert method_auth.auth_type == AuthType.HMAC

    def test_validation_auth_required_without_type(self):
        """Test that auth_type is required when auth_required is True."""
        with pytest.raises(ValueError, match="auth_type must be specified"):
            MethodAuth(auth_required=True, auth_type=None)

    def test_validation_auth_type_without_required(self):
        """Test that auth_type should be None when auth_required is False."""
        with pytest.raises(ValueError, match="auth_type should be None"):
            MethodAuth(auth_required=False, auth_type=AuthType.API_KEY)

    def test_to_dict_no_auth(self):
        """Test serialization of MethodAuth with no auth required."""
        method_auth = MethodAuth(auth_required=False)
        result = method_auth.to_dict()
        assert result == {
            'auth_required': False,
            'auth_type': None
        }

    def test_to_dict_with_auth(self):
        """Test serialization of MethodAuth with auth required."""
        method_auth = MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
        result = method_auth.to_dict()
        assert result == {
            'auth_required': True,
            'auth_type': 'hmac'
        }

    def test_from_dict_no_auth(self):
        """Test deserialization of MethodAuth with no auth required."""
        data = {'auth_required': False, 'auth_type': None}
        method_auth = MethodAuth.from_dict(data)
        assert method_auth.auth_required is False
        assert method_auth.auth_type is None

    def test_from_dict_with_auth(self):
        """Test deserialization of MethodAuth with auth required."""
        data = {'auth_required': True, 'auth_type': 'api_key'}
        method_auth = MethodAuth.from_dict(data)
        assert method_auth.auth_required is True
        assert method_auth.auth_type == AuthType.API_KEY


class TestRoute:
    """Test Route model."""

    def test_create_route_basic(self):
        """Test creating a basic route."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/test',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False)
            },
            created_at=now,
            updated_at=now,
            route_id='test-route'
        )
        assert route.route_id == 'test-route'
        assert route.route_pattern == '/api/test'
        assert route.service_name == 'test-service'
        assert len(route.methods) == 1

    def test_create_route_multiple_methods(self):
        """Test creating route with multiple HTTP methods."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/test',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC),
                HttpMethod.DELETE: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
            },
            created_at=now,
            updated_at=now
        ,
            route_id='test-route'
        )
        assert len(route.methods) == 3
        assert route.methods[HttpMethod.GET].auth_required is False
        assert route.methods[HttpMethod.POST].auth_type == AuthType.HMAC
        assert route.methods[HttpMethod.DELETE].auth_type == AuthType.API_KEY

    def test_validation_route_pattern_must_start_with_slash(self):
        """Test that route pattern must start with /."""
        now = int(time.time())
        with pytest.raises(ValueError, match="route_pattern must start with /"):
            Route(
            route_pattern='api/test',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
            created_at=now,
            updated_at=now
            ,
            route_id='test'
        )

    def test_validation_wildcard_must_be_at_end(self):
        """Test that wildcard must only appear at the end as /*."""
        now = int(time.time())
        with pytest.raises(ValueError, match="Wildcard .* must only appear at the end"):
            Route(
            route_pattern='/api/*/test',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
            created_at=now,
            updated_at=now
            ,
            route_id='test'
        )

    def test_validation_only_one_wildcard(self):
        """Test that only one wildcard is allowed."""
        now = int(time.time())
        with pytest.raises(ValueError, match="Only one wildcard is allowed"):
            Route(
            route_pattern='/api/*/*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
            created_at=now,
            updated_at=now
            ,
            route_id='test'
        )

    def test_validation_at_least_one_method_required(self):
        """Test that at least one HTTP method must be defined."""
        now = int(time.time())
        with pytest.raises(ValueError, match="At least one HTTP method must be defined"):
            Route(
                route_pattern='/api/test',
                service_name='test-service',
                methods={},
                created_at=now,
                updated_at=now,
                route_id='test'
            )

    def test_matches_exact_path(self):
        """Test exact path matching."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/users',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
            created_at=now,
            updated_at=now
        ,
            route_id='test'
        )
        assert route.matches('/api/users') is True
        assert route.matches('/api/users/123') is False
        assert route.matches('/api/user') is False

    def test_matches_wildcard_path(self):
        """Test wildcard path matching."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/users/*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
            created_at=now,
            updated_at=now
        ,
            route_id='test'
        )
        assert route.matches('/api/users/') is True
        assert route.matches('/api/users/123') is True
        assert route.matches('/api/users/123/profile') is True
        assert route.matches('/api/user/123') is False

    def test_get_auth_requirements(self):
        """Test getting auth requirements for a specific method."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/test',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
            },
            created_at=now,
            updated_at=now
        ,
            route_id='test'
        )
        get_auth = route.get_auth_requirements(HttpMethod.GET)
        assert get_auth.auth_required is False

        post_auth = route.get_auth_requirements(HttpMethod.POST)
        assert post_auth.auth_required is True
        assert post_auth.auth_type == AuthType.HMAC

        delete_auth = route.get_auth_requirements(HttpMethod.DELETE)
        assert delete_auth is None

    def test_requires_auth(self):
        """Test checking if a method requires authentication."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/test',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
            },
            created_at=now,
            updated_at=now
        ,
            route_id='test'
        )
        assert route.requires_auth(HttpMethod.GET) is False
        assert route.requires_auth(HttpMethod.POST) is True
        assert route.requires_auth(HttpMethod.DELETE) is False

    def test_to_dict(self):
        """Test serialization to dictionary."""
        now = int(time.time())
        route = Route(
            route_pattern='/api/test',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
            },
            created_at=now,
            updated_at=now
        ,
            route_id='test-route'
        )
        result = route.to_dict()
        assert result['route_id'] == 'test-route'
        assert result['route_pattern'] == '/api/test'
        assert result['service_name'] == 'test-service'
        assert result['created_at'] == now
        assert result['updated_at'] == now
        assert 'GET' in result['methods']
        assert 'POST' in result['methods']
        assert result['methods']['GET']['auth_required'] is False
        assert result['methods']['POST']['auth_type'] == 'hmac'

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        now = int(time.time())
        data = {
            'route_id': 'test-route',
            'route_pattern': '/api/test',
            'service_name': 'test-service',
            'methods': {
                'GET': {'auth_required': False, 'auth_type': None},
                'POST': {'auth_required': True, 'auth_type': 'hmac'}
            },
            'created_at': now,
            'updated_at': now
        }
        route = Route.from_dict(data)
        assert route.route_id == 'test-route'
        assert route.route_pattern == '/api/test'
        assert route.service_name == 'test-service'
        assert len(route.methods) == 2
        assert route.methods[HttpMethod.GET].auth_required is False
        assert route.methods[HttpMethod.POST].auth_type == AuthType.HMAC

    def test_create_new_factory_method(self):
        """Test Route.create_new() factory method sets timestamps."""
        before = int(time.time())
        route = Route.create_new(
            route_pattern='/api/test',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
            route_id='test-route'
        )
        after = int(time.time())

        assert route.route_id == 'test-route'
        assert before <= route.created_at <= after
        assert before <= route.updated_at <= after
        assert route.created_at == route.updated_at
