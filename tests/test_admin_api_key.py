"""
Integration tests for the X-Gatekeeper-Admin-Key auth path on /api/admin/*.

The admin API key is a long-lived shared secret in GATEKEEPER_ADMIN_API_KEY.
Services (e.g. mcp-gatekeeper) use it instead of an Aegis bearer token for
service-to-service admin reads, since Aegis tokens expire in 1 hour and
break long-running consumers.

Read-only by design: the key permits GET only — POST/PUT/DELETE still
require a real Aegis ConsoleAdmin token.
"""
import time

import pytest
from api_gatekeeper_models import Client

from src.app import create_app
from src.auth import HMACHandler


ADMIN_KEY = 'test-admin-api-key-do-not-use-in-prod'


@pytest.fixture
def admin_key_client(clean_db, monkeypatch):
    """App configured with GATEKEEPER_ADMIN_API_KEY set; Aegis NOT mocked."""
    monkeypatch.setenv('GATEKEEPER_ADMIN_API_KEY', ADMIN_KEY)
    monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client, clean_db


def _key(value: str = ADMIN_KEY) -> dict:
    return {'X-Gatekeeper-Admin-Key': value}


class TestAdminKeyReadPath:
    def test_valid_key_get_clients_returns_200(self, admin_key_client):
        client, _ = admin_key_client
        response = client.get('/api/admin/clients', headers=_key())
        assert response.status_code == 200
        assert response.get_json() == []

    def test_valid_key_get_routes_returns_200(self, admin_key_client):
        client, _ = admin_key_client
        response = client.get('/api/admin/routes', headers=_key())
        assert response.status_code == 200

    def test_valid_key_get_permissions_returns_200(self, admin_key_client):
        client, _ = admin_key_client
        response = client.get('/api/admin/permissions', headers=_key())
        assert response.status_code == 200

    def test_valid_key_get_rate_limits_returns_200(self, admin_key_client):
        client, _ = admin_key_client
        response = client.get('/api/admin/rate-limits', headers=_key())
        assert response.status_code == 200

    def test_valid_key_head_returns_200(self, admin_key_client):
        """HEAD is logically a GET-without-body — Flask routes it to the
        same view function. The decorator must allow it so health checkers
        and clients doing existence probes don't get a misleading 403."""
        client, _ = admin_key_client
        response = client.head('/api/admin/clients', headers=_key())
        assert response.status_code == 200

    def test_valid_key_options_does_not_403(self, admin_key_client):
        """OPTIONS is the CORS preflight verb. Real browsers don't include
        custom headers on preflight, but if a misbehaving client does the
        decorator must not collapse the request to a 403 — let Flask's
        method-resolution handle it."""
        client, _ = admin_key_client
        response = client.options('/api/admin/clients', headers=_key())
        # Flask's auto-OPTIONS returns 200 with an Allow header.
        assert response.status_code != 403

    def test_response_uses_clientsummary_redaction(self, admin_key_client):
        """The api-key path goes through the same ClientSummary.to_dict()
        as the console-admin path — shared_secret never reaches the wire."""
        client, db = admin_key_client
        db.save_client(Client.create_new(
            client_name='svc',
            shared_secret='LEAK-CANARY-XYZ',
            api_key='ak_full_key_value_abc',
        ))
        response = client.get('/api/admin/clients', headers=_key())
        raw = response.get_data(as_text=True)
        assert 'LEAK-CANARY-XYZ' not in raw
        assert 'shared_secret' not in raw


class TestAdminKeyAuthFailures:
    def test_wrong_key_returns_401(self, admin_key_client):
        client, _ = admin_key_client
        response = client.get('/api/admin/clients', headers=_key('not-the-key'))
        assert response.status_code == 401

    def test_empty_key_falls_through_to_aegis_path(self, admin_key_client):
        """An empty X-Gatekeeper-Admin-Key header is treated as 'not present'
        — the decorator falls through to the Aegis path, which then 401s
        because no bearer was provided either."""
        client, _ = admin_key_client
        response = client.get('/api/admin/clients', headers={'X-Gatekeeper-Admin-Key': ''})
        assert response.status_code == 401

    def test_env_var_unset_rejects_any_key(self, clean_db, monkeypatch):
        """If GATEKEEPER_ADMIN_API_KEY isn't set, the auth path must NEVER
        accept any X-Gatekeeper-Admin-Key value — including an empty one."""
        monkeypatch.delenv('GATEKEEPER_ADMIN_API_KEY', raising=False)
        monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
        hmac_handler = HMACHandler(clean_db, nonce_storage={})
        app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get('/api/admin/clients', headers=_key('anything'))
            assert response.status_code == 401

    def test_whitespace_env_var_rejected(self, clean_db, monkeypatch):
        """A fat-finger that sets the env var to whitespace (e.g. a yaml
        manifest with trailing whitespace) must NOT auth a whitespace-only
        provided key as 'matching'. validate_admin_api_key strips the env
        value before compare; empty after strip means 'no key configured'."""
        monkeypatch.setenv('GATEKEEPER_ADMIN_API_KEY', '   ')
        monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test')
        hmac_handler = HMACHandler(clean_db, nonce_storage={})
        app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get('/api/admin/clients', headers=_key('   '))
            assert response.status_code == 401


class TestAdminKeyReadOnlyEnforcement:
    def test_post_with_valid_key_returns_403(self, admin_key_client):
        client, _ = admin_key_client
        response = client.post(
            '/api/admin/clients',
            headers={**_key(), 'Content-Type': 'application/json'},
            json={'client_name': 'evil', 'shared_secret': 'x'},
        )
        assert response.status_code == 403
        assert 'read-only' in response.get_json()['error'].lower()

    def test_put_with_valid_key_returns_403(self, admin_key_client):
        client, db = admin_key_client
        seeded = Client.create_new(client_name='alpha', api_key='ak_x123', shared_secret='s')
        db.save_client(seeded)
        response = client.put(
            f'/api/admin/clients/{seeded.client_id}',
            headers={**_key(), 'Content-Type': 'application/json'},
            json={'client_name': 'alpha-updated'},
        )
        assert response.status_code == 403

    def test_delete_with_valid_key_returns_403(self, admin_key_client):
        client, db = admin_key_client
        seeded = Client.create_new(client_name='alpha', api_key='ak_x123', shared_secret='s')
        db.save_client(seeded)
        response = client.delete(
            f'/api/admin/clients/{seeded.client_id}',
            headers=_key(),
        )
        assert response.status_code == 403


class TestAdminKeyActorIdentity:
    def test_actor_logged_as_service(self, admin_key_client, caplog):
        """Audit identity for env-key requests must surface as 'service:*'
        so log lines distinguish service-from-env-key vs human-from-UI.
        The blueprint's _admin_log_extra() reads admin.admin_id and
        admin.email, which our ServiceActor exposes with the `service:` prefix.
        """
        from src.auth import ServiceActor
        actor = ServiceActor(name='admin-api-key')
        assert actor.admin_id.startswith('service:')
        assert actor.email.startswith('service:')
