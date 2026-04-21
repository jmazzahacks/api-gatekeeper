"""
Integration tests for GET /api/admin/routes.

Covers: 401 without bearer, 401 for unprovisioned Aegis user, 200 with
empty list, 200 with seeded routes. Patches AegisClient.me() for auth.
"""
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
AEGIS_USER_ID = 7
EMAIL = 'admin@example.com'


def _user() -> User:
    now = int(time.time())
    return User(
        id=AEGIS_USER_ID,
        site_id=1,
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
    clean_db.create_admin(ConsoleAdmin.create_new(aegis_user_id=AEGIS_USER_ID, email=EMAIL))
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
