"""
Integration tests for GET /api/admin/clients.

Covers: 401 without bearer, 401 for unprovisioned Aegis user, 200 with empty
list, 200 with seeded clients, and — most importantly — that shared_secret is
never returned and api_key is masked.
"""
import logging
import time
import pytest

from api_gatekeeper_models import Client, ClientStatus, ConsoleAdmin
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
    monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
    fake_me[BEARER_VALID] = _user()

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def _bearer(token: str = BEARER_VALID) -> dict:
    return {'Authorization': f'Bearer {token}'}


class TestListClientsAuth:
    def test_no_authorization_header_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/clients')
        assert response.status_code == 401

    def test_invalid_bearer_returns_401(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/clients', headers=_bearer('tok_bogus'))
        assert response.status_code == 401

    def test_valid_token_but_not_provisioned_returns_401(self, admin_client_no_admin):
        response = admin_client_no_admin.get('/api/admin/clients', headers=_bearer())
        assert response.status_code == 401


class TestListClientsResponses:
    def test_empty_list_when_no_clients(self, admin_client):
        client, _ = admin_client
        response = client.get('/api/admin/clients', headers=_bearer())
        assert response.status_code == 200
        assert response.get_json() == []

    def test_lists_single_client_with_safe_fields(self, admin_client):
        client, db = admin_client
        seeded = Client.create_new(
            client_name='alpha-service',
            shared_secret='supersecret-do-not-leak',
            api_key='ak_abcdef0123456789xyz',
        )
        db.save_client(seeded)

        response = client.get('/api/admin/clients', headers=_bearer())

        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 1
        row = body[0]
        assert row['client_name'] == 'alpha-service'
        assert row['status'] == 'active'
        assert row['client_id'] == seeded.client_id
        assert isinstance(row['created_at'], int)
        assert isinstance(row['updated_at'], int)

    def test_response_never_contains_shared_secret(self, admin_client):
        """Defense-in-depth: even if the model schema changes, the wire format must not leak."""
        client, db = admin_client
        db.save_client(Client.create_new(
            client_name='gamma',
            shared_secret='HIGHLY-SENSITIVE-HMAC-KEY',
            api_key='ak_aaaaaaaa1111bbbb',
        ))

        response = client.get('/api/admin/clients', headers=_bearer())
        raw = response.get_data(as_text=True)
        assert 'HIGHLY-SENSITIVE-HMAC-KEY' not in raw
        assert 'shared_secret' not in raw

    def test_api_key_is_masked_not_raw(self, admin_client):
        client, db = admin_client
        db.save_client(Client.create_new(
            client_name='delta',
            shared_secret='ssss',
            api_key='ak_full_key_value_xyz12345',
        ))

        response = client.get('/api/admin/clients', headers=_bearer())
        body = response.get_json()
        row = body[0]
        # Full key must not appear in body
        raw = response.get_data(as_text=True)
        assert 'ak_full_key_value_xyz12345' not in raw
        # The masked field must be present and shaped prefix…suffix
        assert 'api_key_masked' in row
        assert row['api_key_masked'] == 'ak_full_…2345'
        # And the raw api_key field should not be in the row at all
        assert 'api_key' not in row

    def test_short_api_key_is_fully_masked(self, admin_client):
        """Defensive: keys shorter than the prefix+suffix lengths are starred entirely."""
        client, db = admin_client
        db.save_client(Client.create_new(
            client_name='legacy',
            shared_secret='ssss',
            api_key='short',
        ))

        response = client.get('/api/admin/clients', headers=_bearer())
        row = response.get_json()[0]
        assert row['api_key_masked'] == '*****'

    def test_boundary_api_key_does_not_leak_via_mask(self, admin_client):
        """Key of exactly prefix+suffix length must not be exposed by the mask.

        A 12-char key with prefix=8 + suffix=4 would otherwise show all 12 chars.
        """
        client, db = admin_client
        boundary_key = 'abcdefgh1234'  # exactly 12 chars
        db.save_client(Client.create_new(
            client_name='boundary',
            shared_secret='ssss',
            api_key=boundary_key,
        ))

        response = client.get('/api/admin/clients', headers=_bearer())
        row = response.get_json()[0]
        assert row['api_key_masked'] == '*' * 12
        # And the raw key must not appear anywhere in the body.
        assert boundary_key not in response.get_data(as_text=True)

    def test_lists_multiple_clients_alphabetically(self, admin_client):
        """Driver returns ORDER BY client_name; verify the endpoint preserves that."""
        client, db = admin_client
        db.save_client(Client.create_new(
            client_name='zeta',
            shared_secret='secret-zeta', api_key='ak_zeta_xxxxxxxx',
        ))
        db.save_client(Client.create_new(
            client_name='alpha',
            shared_secret='secret-alpha', api_key='ak_alpha_xxxxxxx',
        ))
        db.save_client(Client.create_new(
            client_name='mu',
            shared_secret='secret-mu', api_key='ak_mu_xxxxxxxxxx',
        ))

        response = client.get('/api/admin/clients', headers=_bearer())
        body = response.get_json()
        assert [r['client_name'] for r in body] == ['alpha', 'mu', 'zeta']

    def test_status_serialized_as_string(self, admin_client):
        client, db = admin_client
        seeded = Client.create_new(
            client_name='paused',
            shared_secret='s',
            api_key='ak_paused_xxxxxxx',
            status=ClientStatus.SUSPENDED,
        )
        db.save_client(seeded)

        response = client.get('/api/admin/clients', headers=_bearer())
        assert response.get_json()[0]['status'] == 'suspended'


class TestCreateClient:
    def test_generate_both_credentials_returns_raw_values(self, admin_client):
        client, db = admin_client
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'mobile-app',
                'api_key': {'generate': True},
                'shared_secret': {'generate': True},
            },
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body['client_id']
        assert body['client_name'] == 'mobile-app'
        assert body['api_key']  # full raw value (not masked)
        assert body['shared_secret']
        assert len(body['api_key']) >= 30
        assert len(body['shared_secret']) >= 30
        assert body['status'] == 'active'

        # Verify it was actually persisted with the same values
        stored = db.load_client_by_id(body['client_id'])
        assert stored.api_key == body['api_key']
        assert stored.shared_secret == body['shared_secret']

    def test_custom_api_key_used_as_is(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'legacy-svc',
                'api_key': {'value': 'ak_provided_value_12345'},
                'shared_secret': None,
            },
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body['api_key'] == 'ak_provided_value_12345'
        assert body['shared_secret'] is None

    def test_no_credentials_rejected(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'creds-required',
                'api_key': None,
                'shared_secret': None,
            },
        )
        assert response.status_code == 400

    def test_missing_client_name_rejected(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={'api_key': {'generate': True}},
        )
        assert response.status_code == 400

    def test_invalid_status_rejected(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'bad-status',
                'api_key': {'generate': True},
                'status': 'frozen',
            },
        )
        assert response.status_code == 400

    def test_credential_with_both_generate_and_value_rejected(self, admin_client):
        client, _ = admin_client
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'ambiguous',
                'api_key': {'generate': True, 'value': 'x'},
            },
        )
        assert response.status_code == 400

    def test_duplicate_custom_api_key_returns_409(self, admin_client):
        """Schema has UNIQUE on api_key; a colliding custom value must surface as 409, not 500."""
        client, db = admin_client
        db.save_client(Client.create_new(
            client_name='first', api_key='ak_collision_value', shared_secret=None,
        ))
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'second',
                'api_key': {'value': 'ak_collision_value'},
                'shared_secret': None,
            },
        )
        assert response.status_code == 409
        body = response.get_json()
        assert body['error'] == 'conflict'
        assert 'api_key' in body['message']

    def test_duplicate_custom_shared_secret_returns_409(self, admin_client):
        client, db = admin_client
        db.save_client(Client.create_new(
            client_name='first', api_key=None, shared_secret='hmac-collision',
        ))
        response = client.post(
            '/api/admin/clients',
            headers=_bearer(),
            json={
                'client_name': 'second',
                'api_key': None,
                'shared_secret': {'value': 'hmac-collision'},
            },
        )
        assert response.status_code == 409
        assert 'shared_secret' in response.get_json()['message']

    def test_create_requires_authorization(self, admin_client):
        client, _ = admin_client
        response = client.post('/api/admin/clients', json={})
        assert response.status_code == 401


class TestUpdateClient:
    def _seed(self, db) -> Client:
        c = Client.create_new(
            client_name='before',
            shared_secret='s', api_key='ak_existing_xxxxxx',
            status=ClientStatus.ACTIVE,
        )
        db.save_client(c)
        return c

    def test_rename_and_status_change(self, admin_client):
        client, db = admin_client
        seeded = self._seed(db)

        response = client.put(
            f'/api/admin/clients/{seeded.client_id}',
            headers=_bearer(),
            json={'client_name': 'after', 'status': 'suspended'},
        )
        assert response.status_code == 200
        body = response.get_json()
        # Response is the redacted ClientSummary — secrets must not appear
        assert 'shared_secret' not in body
        assert 'api_key' not in body
        assert body['client_name'] == 'after'
        assert body['status'] == 'suspended'

        # Underlying record retains the original secrets
        stored = db.load_client_by_id(seeded.client_id)
        assert stored.api_key == 'ak_existing_xxxxxx'
        assert stored.shared_secret == 's'
        assert stored.client_name == 'after'
        assert stored.status == ClientStatus.SUSPENDED

    def test_unknown_id_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.put(
            '/api/admin/clients/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
            json={'client_name': 'x', 'status': 'active'},
        )
        assert response.status_code == 404

    def test_missing_status_rejected(self, admin_client):
        client, db = admin_client
        seeded = self._seed(db)
        response = client.put(
            f'/api/admin/clients/{seeded.client_id}',
            headers=_bearer(),
            json={'client_name': 'x'},
        )
        assert response.status_code == 400

    def test_update_requires_authorization(self, admin_client):
        client, db = admin_client
        seeded = self._seed(db)
        response = client.put(f'/api/admin/clients/{seeded.client_id}', json={})
        assert response.status_code == 401


class TestDeleteClient:
    def test_delete_removes_record(self, admin_client):
        client, db = admin_client
        seeded = Client.create_new(
            client_name='gone',
            shared_secret='s', api_key='ak_gone_xxxxxxxxx',
        )
        db.save_client(seeded)

        response = client.delete(
            f'/api/admin/clients/{seeded.client_id}', headers=_bearer(),
        )
        assert response.status_code == 204
        assert db.load_client_by_id(seeded.client_id) is None

    def test_unknown_id_returns_404(self, admin_client):
        client, _ = admin_client
        response = client.delete(
            '/api/admin/clients/00000000-0000-0000-0000-000000000000',
            headers=_bearer(),
        )
        assert response.status_code == 404

    def test_delete_requires_authorization(self, admin_client):
        client, db = admin_client
        seeded = Client.create_new(
            client_name='gone',
            shared_secret='s', api_key='ak_gone_xxxxxxxxx',
        )
        db.save_client(seeded)
        response = client.delete(f'/api/admin/clients/{seeded.client_id}')
        assert response.status_code == 401


class TestClientAuditLogging:
    """Regression guard: each mutation emits a structured audit line tagged
    with the admin's email so post-incident review can attribute the change."""

    def _audit_records(self, caplog) -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.name == 'src.blueprints.admin']

    def test_create_emits_audit_log(self, admin_client, caplog):
        client, _ = admin_client
        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.post(
                '/api/admin/clients',
                headers=_bearer(),
                json={
                    'client_name': 'audited',
                    'api_key': {'generate': True},
                    'shared_secret': None,
                },
            )
        assert response.status_code == 201
        records = self._audit_records(caplog)
        created = next(r for r in records if r.message == 'Client created')
        assert created.admin_email == EMAIL
        assert created.client_name == 'audited'
        assert created.has_api_key is True
        assert created.has_shared_secret is False
        # Raw secret must never reach the log record
        assert 'api_key' not in {k for k in created.__dict__ if k == 'api_key'}

    def test_update_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        seeded = Client.create_new(
            client_name='before', api_key='ak_audit_xxxxxxxx', shared_secret=None,
        )
        db.save_client(seeded)

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.put(
                f'/api/admin/clients/{seeded.client_id}',
                headers=_bearer(),
                json={'client_name': 'after', 'status': 'suspended'},
            )
        assert response.status_code == 200
        records = self._audit_records(caplog)
        updated = next(r for r in records if r.message == 'Client updated')
        assert updated.admin_email == EMAIL
        assert updated.client_id == seeded.client_id
        assert updated.client_name == 'after'
        assert updated.status == 'suspended'

    def test_delete_emits_audit_log(self, admin_client, caplog):
        client, db = admin_client
        seeded = Client.create_new(
            client_name='gone-with-audit',
            api_key='ak_audit_del_xxxxx', shared_secret=None,
        )
        db.save_client(seeded)

        with caplog.at_level(logging.INFO, logger='src.blueprints.admin'):
            response = client.delete(
                f'/api/admin/clients/{seeded.client_id}', headers=_bearer(),
            )
        assert response.status_code == 204
        records = self._audit_records(caplog)
        deleted = next(r for r in records if r.message == 'Client deleted')
        assert deleted.admin_email == EMAIL
        assert deleted.client_id == seeded.client_id
        assert deleted.client_name == 'gone-with-audit'
