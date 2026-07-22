"""
Integration tests for /api/admin/rate-limits endpoints.

Covers auth, list/set/delete semantics, upsert behavior, validation errors,
join-with-client_name in the response shape, and audit logging.
"""
import logging
import time
import pytest

from api_gatekeeper_models import (
    Client,
    ConsoleAdmin,
    RateLimit,
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


def _bearer(token: str = BEARER_VALID) -> dict:
    return {'Authorization': f'Bearer {token}'}


def _seed_client(db, name: str, api_key: str) -> Client:
    c = Client.create_new(client_name=name, api_key=api_key)
    db.save_client(c)
    return c


class TestListRateLimitsAuth:
    def test_no_authorization_header_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/rate-limits')
        assert response.status_code == 401

    def test_invalid_bearer_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/rate-limits', headers=_bearer('tok_bogus'))
        assert response.status_code == 401


class TestListRateLimits:
    def test_empty_returns_empty_list(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/rate-limits', headers=_bearer())
        assert response.status_code == 200
        assert response.get_json() == []

    def test_returns_rows_with_client_name_joined(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        db.save_rate_limit(RateLimit.create_new(client_id=c.client_id, requests_per_day=1000))

        response = client.get('/api/admin/rate-limits', headers=_bearer())
        assert response.status_code == 200
        rows = response.get_json()
        assert len(rows) == 1
        assert rows[0]['client_id'] == c.client_id
        assert rows[0]['client_name'] == 'alpha'
        assert rows[0]['requests_per_day'] == 1000
        assert 'created_at' in rows[0]
        assert 'updated_at' in rows[0]


class TestSetRateLimit:
    def test_first_set_returns_201(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')

        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={'requests_per_day': 500},
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body['client_id'] == c.client_id
        assert body['client_name'] == 'alpha'
        assert body['requests_per_day'] == 500

        stored = db.load_rate_limit_by_client(c.client_id)
        assert stored.requests_per_day == 500

    def test_second_set_returns_200_and_updates(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        db.save_rate_limit(RateLimit.create_new(client_id=c.client_id, requests_per_day=100))

        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={'requests_per_day': 2500},
        )
        assert response.status_code == 200
        assert response.get_json()['requests_per_day'] == 2500

        stored = db.load_rate_limit_by_client(c.client_id)
        assert stored.requests_per_day == 2500

    def test_unknown_client_returns_400(self, admin_client):
        client, _ = admin_client
        response = client.put(
            '/api/admin/rate-limits/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
            json={'requests_per_day': 100},
        )
        assert response.status_code == 400
        assert 'client_id' in response.get_json()['message']

    def test_missing_body_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={},
        )
        assert response.status_code == 400

    def test_zero_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={'requests_per_day': 0},
        )
        assert response.status_code == 400

    def test_negative_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={'requests_per_day': -1},
        )
        assert response.status_code == 400

    def test_non_integer_returns_400(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={'requests_per_day': '500'},
        )
        assert response.status_code == 400

    def test_bool_rejected(self, admin_client):
        """Python's bool is a subclass of int — guard against True sneaking in."""
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            headers=_bearer(),
            json={'requests_per_day': True},
        )
        assert response.status_code == 400

    def test_requires_authorization(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.put(
            f'/api/admin/rate-limits/{c.client_id}',
            json={'requests_per_day': 100},
        )
        assert response.status_code == 401


class TestDeleteRateLimit:
    def test_delete_removes_record(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        db.save_rate_limit(RateLimit.create_new(client_id=c.client_id, requests_per_day=100))

        response = client.delete(
            f'/api/admin/rate-limits/{c.client_id}', headers=_bearer(),
        )
        assert response.status_code == 204
        assert db.load_rate_limit_by_client(c.client_id) is None

    def test_unknown_client_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.delete(
            '/api/admin/rate-limits/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
        )
        assert response.status_code == 404

    def test_no_limit_set_returns_404(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        response = client.delete(
            f'/api/admin/rate-limits/{c.client_id}', headers=_bearer(),
        )
        assert response.status_code == 404

    def test_requires_authorization(self, admin_client):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        db.save_rate_limit(RateLimit.create_new(client_id=c.client_id, requests_per_day=100))
        response = client.delete(f'/api/admin/rate-limits/{c.client_id}')
        assert response.status_code == 401


class TestRateLimitAuditLogging:
    """Each mutation must emit a structured audit line with admin identity."""

    def _audit_records(self, caplog) -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.name == 'src.blueprints.admin']

    def test_set_first_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        c = _seed_client(db, 'alpha-audit', 'ak_alpha_audit__')

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.put(
                f'/api/admin/rate-limits/{c.client_id}',
                headers=_bearer(),
                json={'requests_per_day': 100},
            )
        assert response.status_code == 201
        record = next(r for r in self._audit_records(caplog) if r.message == 'Rate limit set')
        assert record.admin_email == EMAIL
        assert record.client_id == c.client_id
        assert record.client_name == 'alpha-audit'
        assert record.requests_per_day == 100

    def test_set_again_emits_update_audit_log(self, admin_client, caplog):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        db.save_rate_limit(RateLimit.create_new(client_id=c.client_id, requests_per_day=100))

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.put(
                f'/api/admin/rate-limits/{c.client_id}',
                headers=_bearer(),
                json={'requests_per_day': 250},
            )
        assert response.status_code == 200
        record = next(r for r in self._audit_records(caplog) if r.message == 'Rate limit updated')
        assert record.admin_email == EMAIL
        assert record.requests_per_day == 250

    def test_delete_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        c = _seed_client(db, 'alpha', 'ak_alpha_xxxxxxx')
        db.save_rate_limit(RateLimit.create_new(client_id=c.client_id, requests_per_day=100))

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.delete(
                f'/api/admin/rate-limits/{c.client_id}', headers=_bearer(),
            )
        assert response.status_code == 204
        record = next(r for r in self._audit_records(caplog) if r.message == 'Rate limit removed')
        assert record.admin_email == EMAIL
        assert record.client_id == c.client_id
        assert record.requests_per_day == 100
