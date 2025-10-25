"""
Unit tests for database driver CRUD operations.
CRITICAL: All tests use the api_auth_admin_test database via fixtures.
"""
import pytest
import time
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType


class TestDatabaseConnection:
    """Test database connection and setup."""

    def test_db_connection(self, db):
        """Test that database connection is established."""
        assert db is not None
        assert db.pool is not None
        assert not db.pool.closed

    def test_db_cleanup(self, clean_db):
        """Test that clean_db fixture provides empty database."""
        routes = clean_db.load_all_routes()
        assert routes == []


class TestSaveRoute:
    """Test saving routes to database."""

    def test_save_new_route(self, clean_db):
        """Test saving a new route."""
        route = Route.create_new(
            route_pattern='/api/test',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )

        route_id = clean_db.save_route(route)

        assert route_id is not None
        assert route.route_id == route_id

        loaded = clean_db.load_route_by_id(route_id)
        assert loaded is not None
        assert loaded.route_id == route_id
        assert loaded.route_pattern == '/api/test'
        assert loaded.service_name == 'test-service'

    def test_save_route_with_multiple_methods(self, clean_db):
        """Test saving route with multiple HTTP methods."""
        route = Route.create_new(
            route_pattern='/api/users/*',
            service_name='user-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC),
                HttpMethod.DELETE: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
            }
        )

        route_id = clean_db.save_route(route)

        loaded = clean_db.load_route_by_id(route_id)
        assert loaded is not None
        assert len(loaded.methods) == 3
        assert loaded.methods[HttpMethod.GET].auth_required is False
        assert loaded.methods[HttpMethod.POST].auth_type == AuthType.HMAC
        assert loaded.methods[HttpMethod.DELETE].auth_type == AuthType.API_KEY

    def test_save_route_upsert_updates_existing(self, clean_db):
        """Test that saving an existing route updates it (upsert behavior)."""
        route = Route.create_new(
            route_pattern='/api/test',
            service_name='service-v1',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        time.sleep(1)

        # Update route with same ID
        updated_route = Route.create_new(
            route_pattern='/api/test/v2',
            service_name='service-v2',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)},
            route_id=route_id
        )
        clean_db.save_route(updated_route)

        loaded = clean_db.load_route_by_id(route_id)
        assert loaded.route_pattern == '/api/test/v2'
        assert loaded.service_name == 'service-v2'
        assert HttpMethod.POST in loaded.methods
        assert loaded.updated_at > loaded.created_at


class TestLoadRouteById:
    """Test loading routes by ID."""

    def test_load_existing_route(self, clean_db):
        """Test loading a route that exists."""
        route = Route.create_new(
            route_pattern='/api/load',
            service_name='load-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        loaded = clean_db.load_route_by_id(route_id)
        assert loaded is not None
        assert loaded.route_id == route_id

    def test_load_nonexistent_route(self, clean_db):
        """Test loading a route that doesn't exist returns None."""
        loaded = clean_db.load_route_by_id('00000000-0000-0000-0000-000000000000')
        assert loaded is None


class TestLoadRouteByPattern:
    """Test loading routes by pattern."""

    def test_load_by_exact_pattern(self, clean_db):
        """Test loading route by exact pattern match."""
        route = Route.create_new(
            route_pattern='/api/exact/path',
            service_name='pattern-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        loaded = clean_db.load_route_by_pattern('/api/exact/path')
        assert loaded is not None
        assert loaded.route_id == route_id

    def test_load_by_wildcard_pattern(self, clean_db):
        """Test loading route by wildcard pattern."""
        route = Route.create_new(
            route_pattern='/api/users/*',
            service_name='user-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        loaded = clean_db.load_route_by_pattern('/api/users/*')
        assert loaded is not None
        assert loaded.route_id == route_id

    def test_load_by_pattern_not_found(self, clean_db):
        """Test loading by pattern that doesn't exist returns None."""
        loaded = clean_db.load_route_by_pattern('/api/nonexistent')
        assert loaded is None


class TestLoadRoutesByService:
    """Test loading routes by service name."""

    def test_load_multiple_routes_for_service(self, clean_db):
        """Test loading all routes for a specific service."""
        route1 = Route.create_new(
            route_pattern='/api/v1/users',
            service_name='user-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route2 = Route.create_new(
            route_pattern='/api/v1/users/*',
            service_name='user-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        route3 = Route.create_new(
            route_pattern='/api/v1/posts',
            service_name='post-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )

        clean_db.save_route(route1)
        clean_db.save_route(route2)
        clean_db.save_route(route3)

        user_routes = clean_db.load_routes_by_service('user-service')
        assert len(user_routes) == 2
        assert all(r.service_name == 'user-service' for r in user_routes)

    def test_load_routes_for_empty_service(self, clean_db):
        """Test loading routes for service with no routes returns empty list."""
        routes = clean_db.load_routes_by_service('nonexistent-service')
        assert routes == []


class TestLoadAllRoutes:
    """Test loading all routes."""

    def test_load_all_routes(self, clean_db):
        """Test loading all routes from database."""
        route1 = Route.create_new(
            route_pattern='/api/route1',
            service_name='service-a',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route2 = Route.create_new(
            route_pattern='/api/route2',
            service_name='service-b',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        route3 = Route.create_new(
            route_pattern='/api/route3',
            service_name='service-a',
            methods={HttpMethod.DELETE: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )

        id1 = clean_db.save_route(route1)
        id2 = clean_db.save_route(route2)
        id3 = clean_db.save_route(route3)

        all_routes = clean_db.load_all_routes()
        assert len(all_routes) == 3
        route_ids = {r.route_id for r in all_routes}
        assert route_ids == {id1, id2, id3}

    def test_load_all_routes_empty_database(self, clean_db):
        """Test loading all routes from empty database returns empty list."""
        routes = clean_db.load_all_routes()
        assert routes == []


class TestFindMatchingRoutes:
    """Test finding routes that match a given path."""

    def test_find_exact_match(self, clean_db):
        """Test finding route with exact path match."""
        route = Route.create_new(
            route_pattern='/api/users',
            service_name='user-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        matches = clean_db.find_matching_routes('/api/users')
        assert len(matches) == 1
        assert matches[0].route_id == route_id

    def test_find_wildcard_match(self, clean_db):
        """Test finding route with wildcard match."""
        route = Route.create_new(
            route_pattern='/api/users/*',
            service_name='user-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        matches = clean_db.find_matching_routes('/api/users/123')
        assert len(matches) == 1
        assert matches[0].route_id == route_id

    def test_find_multiple_matches(self, clean_db):
        """Test finding multiple routes that match a path."""
        route1 = Route.create_new(
            route_pattern='/api/users/123',
            service_name='user-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route2 = Route.create_new(
            route_pattern='/api/users/*',
            service_name='user-service',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)}
        )
        id1 = clean_db.save_route(route1)
        id2 = clean_db.save_route(route2)

        matches = clean_db.find_matching_routes('/api/users/123')
        assert len(matches) == 2
        route_ids = {r.route_id for r in matches}
        assert route_ids == {id1, id2}

    def test_find_no_matches(self, clean_db):
        """Test finding routes when no matches exist."""
        route = Route.create_new(
            route_pattern='/api/users',
            service_name='user-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        matches = clean_db.find_matching_routes('/api/posts')
        assert matches == []


class TestDeleteRoute:
    """Test deleting routes."""

    def test_delete_existing_route(self, clean_db):
        """Test deleting a route that exists."""
        route = Route.create_new(
            route_pattern='/api/delete',
            service_name='delete-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route_id = clean_db.save_route(route)

        result = clean_db.delete_route(route_id)
        assert result is True

        loaded = clean_db.load_route_by_id(route_id)
        assert loaded is None

    def test_delete_nonexistent_route(self, clean_db):
        """Test deleting a route that doesn't exist returns False."""
        result = clean_db.delete_route('00000000-0000-0000-0000-000000000000')
        assert result is False


class TestDatabaseIsolation:
    """Test that tests are properly isolated from each other."""

    def test_isolation_test1(self, clean_db):
        """First test that creates data."""
        route = Route.create_new(
            route_pattern='/api/isolation1',
            service_name='isolation-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        clean_db.save_route(route)

        routes = clean_db.load_all_routes()
        assert len(routes) == 1

    def test_isolation_test2(self, clean_db):
        """Second test should not see data from first test."""
        routes = clean_db.load_all_routes()
        assert len(routes) == 0
