"""
Integration tests for GET /api/admin/routes.

Covers: 401 without bearer, 401 for unprovisioned Aegis user, 200 with
empty list, 200 with seeded routes. Patches AegisClient.me() for auth.
"""
import logging
import time
import pytest

from api_gatekeeper_models import (
    AuthType,
    ConsoleAdmin,
    HttpMethod,
    MethodAuth,
    Route,
)
from byteforge_aegis_client import AegisUnauthorized
from byteforge_aegis_models import User, UserRole

from src.app import create_app
from src.auth import HMACHandler
import src.auth.aegis_authenticator as aegis_auth_module


BEARER_VALID = 'tok_admin'
AEGIS_UUID = 'b8e9dfc0-5ba5-4bbd-a314-cb342eac0f71'
SITE_UUID = '11111111-1111-1111-1111-111111111111'
EMAIL = 'admin@example.com'


def _user() -> User:
    now = int(time.time())
    return User(
        uuid=AEGIS_UUID,
        site_uuid=SITE_UUID,
        email=EMAIL,
        is_verified=True,
        role=UserRole.USER,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def fake_me(monkeypatch):
    mapping: dict[str, object] = {}

    def fake(self):
        token = self.get_auth_token()
        result = mapping.get(token)
        if result is None:
            raise AegisUnauthorized('unknown token')
        return result

    monkeypatch.setattr(aegis_auth_module.AegisClient, 'me', fake)
    return mapping


@pytest.fixture
def admin_client(clean_db, monkeypatch, fake_me):
    """Flask test client with Aegis authenticator configured + one provisioned admin."""
    monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
    clean_db.create_admin(ConsoleAdmin.create_new(email=EMAIL, aegis_uuid=AEGIS_UUID))
    fake_me[BEARER_VALID] = _user()

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client, clean_db


@pytest.fixture
def admin_client_no_admin(clean_db, monkeypatch, fake_me):
    """Authenticator configured, but the Aegis user is not in console_admins."""
    monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
    fake_me[BEARER_VALID] = _user()

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def _bearer(token: str = BEARER_VALID) -> dict:
    return {'Authorization': f'Bearer {token}'}


class TestListRoutesAuth:
    def test_no_authorization_header_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/routes')
        assert response.status_code == 401

    def test_invalid_bearer_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/routes', headers=_bearer('tok_bogus'))
        assert response.status_code == 401

    def test_valid_token_but_not_provisioned_returns_401(self, admin_client_no_admin):
        """Aegis says the token is valid but the user isn't in console_admins."""
        response = admin_client_no_admin.get('/api/admin/routes', headers=_bearer())
        assert response.status_code == 401


class TestListRoutesResponses:
    def test_empty_list_when_no_routes(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/routes', headers=_bearer())

        assert response.status_code == 200
        assert response.get_json() == []

    def test_lists_single_route(self, admin_client):
        client, db = admin_client
        route = Route.create_new(
            route_pattern='/api/test',
            domain='*',
            service_name='test-service',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        db.save_route(route)

        response = client.get('/api/admin/routes', headers=_bearer())

        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 1
        assert body[0]['route_pattern'] == '/api/test'
        assert body[0]['service_name'] == 'test-service'
        assert body[0]['domain'] == '*'
        assert 'GET' in body[0]['methods']

    def test_lists_multiple_routes_with_varied_methods(self, admin_client):
        client, db = admin_client
        db.save_route(Route.create_new(
            route_pattern='/api/public',
            domain='api.example.com',
            service_name='public-svc',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        ))
        db.save_route(Route.create_new(
            route_pattern='/api/users/*',
            domain='*',
            service_name='user-svc',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC),
            },
        ))

        response = client.get('/api/admin/routes', headers=_bearer())
        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 2

        patterns = {r['route_pattern'] for r in body}
        assert patterns == {'/api/public', '/api/users/*'}

        users_route = next(r for r in body if r['route_pattern'] == '/api/users/*')
        assert set(users_route['methods'].keys()) == {'GET', 'POST'}
        assert users_route['methods']['POST']['auth_type'] == 'hmac'


class TestCreateRoute:
    def test_create_route_persists_and_returns_201(self, admin_client):
        client, db = admin_client
        payload = {
            'route_pattern': '/api/widgets',
            'domain': 'api.example.com',
            'service_name': 'widget-svc',
            'methods': {
                'GET': {'auth_required': False, 'auth_type': None},
                'POST': {'auth_required': True, 'auth_type': 'api_key'},
            },
        }

        response = client.post('/api/admin/routes', headers=_bearer(), json=payload)
        assert response.status_code == 201
        body = response.get_json()
        assert body['route_id']
        assert body['route_pattern'] == '/api/widgets'
        assert body['methods']['POST']['auth_type'] == 'api_key'

        stored = db.load_route_by_id(body['route_id'])
        assert stored is not None
        assert stored.service_name == 'widget-svc'

    def test_create_route_requires_authorization(self, admin_client):
        client, _ = admin_client
        response = client.post('/api/admin/routes', json={})
        assert response.status_code == 401

    def test_create_route_rejects_missing_field(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/routes',
            headers=_bearer(),
            json={'domain': '*', 'service_name': 'svc', 'methods': {'GET': {'auth_required': False}}},
        )
        assert response.status_code == 400
        assert 'route_pattern' in response.get_json()['message']

    def test_create_route_rejects_unknown_method(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/routes',
            headers=_bearer(),
            json={
                'route_pattern': '/api/x',
                'domain': '*',
                'service_name': 'svc',
                'methods': {'TRACE': {'auth_required': False}},
            },
        )
        assert response.status_code == 400

    def test_create_route_rejects_auth_required_without_type(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/routes',
            headers=_bearer(),
            json={
                'route_pattern': '/api/x',
                'domain': '*',
                'service_name': 'svc',
                'methods': {'GET': {'auth_required': True}},
            },
        )
        assert response.status_code == 400

    def test_create_route_rejects_pattern_without_leading_slash(self, admin_client):
        """Route() __post_init__ rejects this — endpoint must surface as 400, not 500."""
        client, _ = admin_client
        response = client.post(
            '/api/admin/routes',
            headers=_bearer(),
            json={
                'route_pattern': 'no-leading-slash',
                'domain': '*',
                'service_name': 'svc',
                'methods': {'GET': {'auth_required': False}},
            },
        )
        assert response.status_code == 400


class TestUpdateRoute:
    def _seed_route(self, db) -> Route:
        route = Route.create_new(
            route_pattern='/api/orig',
            domain='*',
            service_name='orig-svc',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        db.save_route(route)
        return route

    def test_update_route_replaces_fields(self, admin_client):
        client, db = admin_client
        route = self._seed_route(db)

        payload = {
            'route_pattern': '/api/renamed',
            'domain': 'api.example.com',
            'service_name': 'renamed-svc',
            'methods': {
                'GET': {'auth_required': True, 'auth_type': 'hmac'},
            },
        }

        response = client.put(
            f'/api/admin/routes/{route.route_id}',
            headers=_bearer(),
            json=payload,
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body['route_id'] == route.route_id
        assert body['route_pattern'] == '/api/renamed'
        assert body['created_at'] == route.created_at
        assert body['updated_at'] >= route.updated_at

        stored = db.load_route_by_id(route.route_id)
        assert stored.service_name == 'renamed-svc'
        assert stored.methods[HttpMethod.GET].auth_type == AuthType.HMAC

    def test_update_route_unknown_id_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.put(
            '/api/admin/routes/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
            json={
                'route_pattern': '/api/x',
                'domain': '*',
                'service_name': 'svc',
                'methods': {'GET': {'auth_required': False}},
            },
        )
        assert response.status_code == 404

    def test_update_route_requires_authorization(self, admin_client):
        client, db = admin_client
        route = self._seed_route(db)
        response = client.put(f'/api/admin/routes/{route.route_id}', json={})
        assert response.status_code == 401

    def test_update_route_validates_payload(self, admin_client):
        client, db = admin_client
        route = self._seed_route(db)
        response = client.put(
            f'/api/admin/routes/{route.route_id}',
            headers=_bearer(),
            json={'route_pattern': '/api/x', 'domain': '*', 'service_name': 'svc', 'methods': {}},
        )
        assert response.status_code == 400

    def test_update_route_rejects_pattern_without_leading_slash(self, admin_client):
        """Regression: Route() __post_init__ runs after parser; must still 400."""
        client, db = admin_client
        route = self._seed_route(db)
        response = client.put(
            f'/api/admin/routes/{route.route_id}',
            headers=_bearer(),
            json={
                'route_pattern': 'no-leading-slash',
                'domain': '*',
                'service_name': 'svc',
                'methods': {'GET': {'auth_required': False}},
            },
        )
        assert response.status_code == 400


class TestDeleteRoute:
    def test_delete_route_removes_record(self, admin_client):
        client, db = admin_client
        route = Route.create_new(
            route_pattern='/api/gone',
            domain='*',
            service_name='gone-svc',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        db.save_route(route)

        response = client.delete(f'/api/admin/routes/{route.route_id}', headers=_bearer())
        assert response.status_code == 204
        assert db.load_route_by_id(route.route_id) is None

    def test_delete_route_unknown_id_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.delete(
            '/api/admin/routes/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
        )
        assert response.status_code == 404

    def test_delete_route_requires_authorization(self, admin_client):
        client, db = admin_client
        route = Route.create_new(
            route_pattern='/api/gone',
            domain='*',
            service_name='gone-svc',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        db.save_route(route)
        response = client.delete(f'/api/admin/routes/{route.route_id}')
        assert response.status_code == 401


class TestRouteAuditLogging:
    """Regression guard: each mutation must emit a structured audit line tagged
    with the admin's email so post-incident review can attribute the change."""

    def _audit_records(self, caplog) -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.name == 'src.blueprints.admin']

    def test_create_emits_audit_log(self, admin_client, caplog):
        client, _ = admin_client
        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.post(
                '/api/admin/routes',
                headers=_bearer(),
                json={
                    'route_pattern': '/api/audit',
                    'domain': '*',
                    'service_name': 'audit-svc',
                    'methods': {'GET': {'auth_required': False}},
                },
            )
        assert response.status_code == 201

        records = self._audit_records(caplog)
        assert any(r.message == 'Route created' for r in records)
        created = next(r for r in records if r.message == 'Route created')
        assert created.admin_email == EMAIL
        assert created.route_pattern == '/api/audit'
        assert created.methods == ['GET']

    def test_update_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        route = Route.create_new(
            route_pattern='/api/orig',
            domain='*',
            service_name='orig-svc',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        db.save_route(route)

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.put(
                f'/api/admin/routes/{route.route_id}',
                headers=_bearer(),
                json={
                    'route_pattern': '/api/renamed',
                    'domain': '*',
                    'service_name': 'orig-svc',
                    'methods': {'GET': {'auth_required': False}},
                },
            )
        assert response.status_code == 200

        records = self._audit_records(caplog)
        updated = next(r for r in records if r.message == 'Route updated')
        assert updated.admin_email == EMAIL
        assert updated.route_id == route.route_id
        assert updated.route_pattern == '/api/renamed'

    def test_delete_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        route = Route.create_new(
            route_pattern='/api/gone',
            domain='*',
            service_name='gone-svc',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)},
        )
        db.save_route(route)

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.delete(f'/api/admin/routes/{route.route_id}', headers=_bearer())
        assert response.status_code == 204

        records = self._audit_records(caplog)
        deleted = next(r for r in records if r.message == 'Route deleted')
        assert deleted.admin_email == EMAIL
        assert deleted.route_id == route.route_id
        assert deleted.route_pattern == '/api/gone'
