"""
Integration tests for GET /api/admin/permissions.

Covers: 401 without bearer, 401 for unprovisioned Aegis user, 200 with empty
list, 200 with seeded permissions, that display fields are joined, and that
allowed_methods serialize as strings.
"""
import logging
import time
import pytest

from api_gatekeeper_models import (
    AuthType,
    Client,
    ClientPermission,
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
    monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
    fake_me[BEARER_VALID] = _user()

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def _bearer(token: str = BEARER_VALID) -> dict:
    return {'Authorization': f'Bearer {token}'}


def _seed_client(db, name: str, secret: str, api_key: str) -> Client:
    c = Client.create_new(client_name=name, shared_secret=secret, api_key=api_key)
    db.save_client(c)
    return c


def _seed_route(db, pattern: str, domain: str, service: str) -> Route:
    r = Route.create_new(
        route_pattern=pattern,
        domain=domain,
        service_name=service,
        methods={HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)},
    )
    db.save_route(r)
    return r


class TestListPermissionsAuth:
    def test_no_authorization_header_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/permissions')
        assert response.status_code == 401

    def test_invalid_bearer_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/permissions', headers=_bearer('tok_bogus'))
        assert response.status_code == 401

    def test_valid_token_but_not_provisioned_returns_401(self, admin_client_no_admin):
        response = admin_client_no_admin.get('/api/admin/permissions', headers=_bearer())
        assert response.status_code == 401


class TestListPermissionsResponses:
    def test_empty_list_when_no_permissions(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/permissions', headers=_bearer())
        assert response.status_code == 200
        assert response.get_json() == []

    def test_lists_single_permission_with_joined_fields(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha-svc', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users/*', 'api.example.com', 'user-svc')

        permission = ClientPermission.create_new(
            client_id=c.client_id,
            route_id=r.route_id,
            allowed_methods=[HttpMethod.GET, HttpMethod.POST],
        )
        db.save_permission(permission)

        response = client.get('/api/admin/permissions', headers=_bearer())
        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 1
        row = body[0]
        assert row['client_id'] == c.client_id
        assert row['client_name'] == 'alpha-svc'
        assert row['route_id'] == r.route_id
        assert row['route_pattern'] == '/api/users/*'
        assert row['route_domain'] == 'api.example.com'
        assert row['route_service_name'] == 'user-svc'
        assert row['allowed_methods'] == ['GET', 'POST']
        assert isinstance(row['created_at'], int)
        assert row['permission_id']

    def test_methods_serialize_as_strings(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'beta', 'secret-beta', 'ak_beta_xxxxxxxx')
        r = _seed_route(db, '/api/orders', '*', 'order-svc')
        db.save_permission(ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.PUT, HttpMethod.DELETE],
        ))

        response = client.get('/api/admin/permissions', headers=_bearer())
        row = response.get_json()[0]
        assert set(row['allowed_methods']) == {'PUT', 'DELETE'}

    def test_lists_multiple_permissions(self, admin_client):
        client, db = admin_client
        c1 = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        c2 = _seed_client(db, 'gamma', 'secret-gamma', 'ak_gamma_xxxxxxx')
        r1 = _seed_route(db, '/api/a', '*', 'svc-a')
        r2 = _seed_route(db, '/api/b', '*', 'svc-b')

        db.save_permission(ClientPermission.create_new(
            client_id=c1.client_id, route_id=r1.route_id, allowed_methods=[HttpMethod.GET]))
        db.save_permission(ClientPermission.create_new(
            client_id=c1.client_id, route_id=r2.route_id, allowed_methods=[HttpMethod.POST]))
        db.save_permission(ClientPermission.create_new(
            client_id=c2.client_id, route_id=r1.route_id, allowed_methods=[HttpMethod.GET]))

        response = client.get('/api/admin/permissions', headers=_bearer())
        body = response.get_json()
        assert len(body) == 3
        # Every row should have its display fields populated.
        for row in body:
            assert row['client_name'] in {'alpha', 'gamma'}
            assert row['route_pattern'] in {'/api/a', '/api/b'}


class TestCreatePermission:
    def test_grants_returns_201_with_joined_summary(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', 'api.example.com', 'user-svc')

        response = client.post(
            '/api/admin/permissions',
            headers=_bearer(),
            json={
                'client_id': c.client_id,
                'route_id': r.route_id,
                'allowed_methods': ['GET', 'POST'],
            },
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body['permission_id']
        assert body['client_id'] == c.client_id
        assert body['client_name'] == 'alpha'
        assert body['route_pattern'] == '/api/users'
        assert set(body['allowed_methods']) == {'GET', 'POST'}

        stored = db.load_permission_by_client_and_route(c.client_id, r.route_id)
        assert stored is not None

    def test_duplicate_pair_returns_409(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', '*', 'user-svc')
        db.save_permission(ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.GET],
        ))

        response = client.post(
            '/api/admin/permissions',
            headers=_bearer(),
            json={
                'client_id': c.client_id,
                'route_id': r.route_id,
                'allowed_methods': ['POST'],
            },
        )
        assert response.status_code == 409
        assert response.get_json()['error'] == 'conflict'

    def test_unknown_client_returns_400(self, admin_client):
        client, db = admin_client
        r = _seed_route(db, '/api/users', '*', 'svc')
        response = client.post(
            '/api/admin/permissions',
            headers=_bearer(),
            json={
                'client_id': '00000000-0000-0000-0000-000000000000',
                'route_id': r.route_id,
                'allowed_methods': ['GET'],
            },
        )
        assert response.status_code == 400
        assert 'client_id' in response.get_json()['message']

    def test_unknown_route_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        response = client.post(
            '/api/admin/permissions',
            headers=_bearer(),
            json={
                'client_id': c.client_id,
                'route_id': '00000000-0000-0000-0000-000000000000',
                'allowed_methods': ['GET'],
            },
        )
        assert response.status_code == 400
        assert 'route_id' in response.get_json()['message']

    def test_empty_methods_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', '*', 'svc')
        response = client.post(
            '/api/admin/permissions',
            headers=_bearer(),
            json={
                'client_id': c.client_id,
                'route_id': r.route_id,
                'allowed_methods': [],
            },
        )
        assert response.status_code == 400

    def test_unknown_method_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', '*', 'svc')
        response = client.post(
            '/api/admin/permissions',
            headers=_bearer(),
            json={
                'client_id': c.client_id,
                'route_id': r.route_id,
                'allowed_methods': ['TRACE'],
            },
        )
        assert response.status_code == 400

    def test_create_requires_authorization(self, admin_client):
        client, _ = admin_client
        response = client.post('/api/admin/permissions', json={})
        assert response.status_code == 401


class TestUpdatePermission:
    def _seed(self, db):
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', '*', 'svc')
        p = ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.GET],
        )
        db.save_permission(p)
        return c, r, p

    def test_update_replaces_methods(self, admin_client):
        client, db = admin_client
        c, r, p = self._seed(db)

        response = client.put(
            f'/api/admin/permissions/{p.permission_id}',
            headers=_bearer(),
            json={'allowed_methods': ['POST', 'DELETE']},
        )
        assert response.status_code == 200
        body = response.get_json()
        assert set(body['allowed_methods']) == {'POST', 'DELETE'}
        assert body['permission_id'] == p.permission_id

        stored = db.load_permission_by_id(p.permission_id)
        assert set(m.value for m in stored.allowed_methods) == {'POST', 'DELETE'}

    def test_unknown_id_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.put(
            '/api/admin/permissions/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
            json={'allowed_methods': ['GET']},
        )
        assert response.status_code == 404

    def test_empty_methods_returns_400(self, admin_client):
        client, db = admin_client
        _, _, p = self._seed(db)
        response = client.put(
            f'/api/admin/permissions/{p.permission_id}',
            headers=_bearer(),
            json={'allowed_methods': []},
        )
        assert response.status_code == 400

    def test_update_requires_authorization(self, admin_client):
        client, db = admin_client
        _, _, p = self._seed(db)
        response = client.put(f'/api/admin/permissions/{p.permission_id}', json={})
        assert response.status_code == 401


class TestDeletePermission:
    def test_delete_removes_record(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', '*', 'svc')
        p = ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.GET],
        )
        db.save_permission(p)

        response = client.delete(
            f'/api/admin/permissions/{p.permission_id}', headers=_bearer(),
        )
        assert response.status_code == 204
        assert db.load_permission_by_id(p.permission_id) is None

    def test_unknown_id_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.delete(
            '/api/admin/permissions/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
        )
        assert response.status_code == 404

    def test_delete_requires_authorization(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'secret-alpha', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/users', '*', 'svc')
        p = ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.GET],
        )
        db.save_permission(p)
        response = client.delete(f'/api/admin/permissions/{p.permission_id}')
        assert response.status_code == 401


class TestPermissionAuditLogging:
    """Regression guard: each mutation must emit a structured audit line tagged
    with the admin's email and the affected client + route."""

    def _audit_records(self, caplog) -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.name == 'src.blueprints.admin']

    def test_create_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        c = _seed_client(db, 'alpha-audit', 'sa', 'ak_alpha_audit__')
        r = _seed_route(db, '/api/audit', '*', 'audit-svc')

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.post(
                '/api/admin/permissions',
                headers=_bearer(),
                json={
                    'client_id': c.client_id,
                    'route_id': r.route_id,
                    'allowed_methods': ['GET'],
                },
            )
        assert response.status_code == 201
        granted = next(r for r in self._audit_records(caplog) if r.message == 'Permission granted')
        assert granted.admin_email == EMAIL
        assert granted.client_id == c.client_id
        assert granted.route_id == r.route_id
        assert granted.allowed_methods == ['GET']

    def test_update_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'sa', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/audit', '*', 'svc')
        p = ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.GET],
        )
        db.save_permission(p)

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.put(
                f'/api/admin/permissions/{p.permission_id}',
                headers=_bearer(),
                json={'allowed_methods': ['POST']},
            )
        assert response.status_code == 200
        updated = next(r for r in self._audit_records(caplog) if r.message == 'Permission updated')
        assert updated.admin_email == EMAIL
        assert updated.permission_id == p.permission_id
        assert updated.allowed_methods == ['POST']

    def test_delete_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'sa', 'ak_alpha_xxxxxxx')
        r = _seed_route(db, '/api/audit', '*', 'svc')
        p = ClientPermission.create_new(
            client_id=c.client_id, route_id=r.route_id,
            allowed_methods=[HttpMethod.GET],
        )
        db.save_permission(p)

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.delete(
                f'/api/admin/permissions/{p.permission_id}', headers=_bearer(),
            )
        assert response.status_code == 204
        revoked = next(r for r in self._audit_records(caplog) if r.message == 'Permission revoked')
        assert revoked.admin_email == EMAIL
        assert revoked.permission_id == p.permission_id
