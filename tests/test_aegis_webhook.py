"""
End-to-end tests for the Aegis webhook endpoint.

Exercises the signature verification, event-type filtering, payload validation,
allowlist gating, and idempotent provisioning (including concurrent-delivery
race safety) against a real test database.
"""
import hmac
import hashlib
import json
import time
import pytest

from src.app import create_app
from src.auth import HMACHandler
from src.blueprints.aegis_webhook import WEBHOOK_PATH


WEBHOOK_SECRET = 'unit_test_webhook_secret_abc123'
ALLOWED_EMAIL = 'admin@example.com'
DENIED_EMAIL = 'stranger@example.com'


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    message = timestamp.encode('utf-8') + b'.' + body
    digest = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _build_request(
    event_type: str = 'user.verified',
    payload: dict = None,
    secret: str = WEBHOOK_SECRET,
    timestamp: str = None,
    signature_override: str = None,
):
    """Produce (headers, body_bytes) for a webhook request."""
    if payload is None:
        payload = {
            'event_type': 'user.verified',
            'site_id': 1,
            'user_id': 42,
            'email': ALLOWED_EMAIL,
            'aegis_role': 'admin',
            'timestamp': int(time.time()),
        }
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    timestamp = timestamp if timestamp is not None else str(int(time.time()))
    signature = signature_override if signature_override is not None else _sign(secret, timestamp, body)

    headers = {
        'Content-Type': 'application/json',
        'X-Aegis-Event': event_type,
        'X-Aegis-Signature': signature,
        'X-Aegis-Timestamp': timestamp,
    }
    return headers, body


@pytest.fixture
def webhook_client(clean_db, monkeypatch):
    """Flask test client with webhook secret and allowlist configured."""
    monkeypatch.setenv('AEGIS_WEBHOOK_SECRET', WEBHOOK_SECRET)
    monkeypatch.setenv('AEGIS_ADMIN_EMAILS', f'{ALLOWED_EMAIL},other-admin@example.com')

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client, clean_db


@pytest.fixture
def webhook_client_no_secret(clean_db, monkeypatch):
    """Flask test client with NO webhook secret configured (misconfiguration case)."""
    monkeypatch.delenv('AEGIS_WEBHOOK_SECRET', raising=False)
    monkeypatch.setenv('AEGIS_ADMIN_EMAILS', ALLOWED_EMAIL)

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def webhook_client_no_allowlist(clean_db, monkeypatch):
    """Flask test client with webhook secret but empty allowlist."""
    monkeypatch.setenv('AEGIS_WEBHOOK_SECRET', WEBHOOK_SECRET)
    monkeypatch.delenv('AEGIS_ADMIN_EMAILS', raising=False)

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client, clean_db


class TestWebhookAuth:
    """Signature verification and misconfiguration handling."""

    def test_missing_secret_returns_503(self, webhook_client_no_secret):
        """503 (not 500) so Aegis gives up rather than retrying into a misconfiguration."""
        headers, body = _build_request()
        response = webhook_client_no_secret.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 503

    def test_invalid_signature_returns_401(self, webhook_client):
        client, _ = webhook_client
        headers, body = _build_request(signature_override='sha256=deadbeef')
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 401

    def test_tampered_body_returns_401(self, webhook_client):
        client, _ = webhook_client
        # Sign a different body than we send
        original_payload = {
            'event_type': 'user.verified',
            'user_id': 42,
            'email': ALLOWED_EMAIL,
            'timestamp': int(time.time()),
        }
        signed_body = json.dumps(original_payload, separators=(',', ':')).encode('utf-8')
        tampered_payload = dict(original_payload, user_id=999)
        tampered_body = json.dumps(tampered_payload, separators=(',', ':')).encode('utf-8')
        timestamp = str(int(time.time()))
        headers = {
            'Content-Type': 'application/json',
            'X-Aegis-Event': 'user.verified',
            'X-Aegis-Signature': _sign(WEBHOOK_SECRET, timestamp, signed_body),
            'X-Aegis-Timestamp': timestamp,
        }
        response = client.post(WEBHOOK_PATH, headers=headers, data=tampered_body)

        assert response.status_code == 401

    def test_stale_timestamp_returns_401(self, webhook_client):
        client, _ = webhook_client
        stale = str(int(time.time()) - 400)  # 400s old, beyond 300s tolerance
        headers, body = _build_request(timestamp=stale)
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 401

    def test_missing_signature_header_returns_401(self, webhook_client):
        client, _ = webhook_client
        _, body = _build_request()
        headers = {
            'Content-Type': 'application/json',
            'X-Aegis-Event': 'user.verified',
            'X-Aegis-Timestamp': str(int(time.time())),
        }
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 401


class TestEventTypeFiltering:
    """Only user.verified events are processed; others return 200 no-op."""

    def test_unknown_event_type_is_ignored(self, webhook_client):
        client, db = webhook_client
        headers, body = _build_request(event_type='user.created')
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 200
        assert response.get_json()['received'] is True
        assert db.get_admin_by_aegis_id(42) is None

    def test_missing_event_type_header_is_ignored(self, webhook_client):
        client, db = webhook_client
        _, body = _build_request()
        timestamp = str(int(time.time()))
        headers = {
            'Content-Type': 'application/json',
            'X-Aegis-Signature': _sign(WEBHOOK_SECRET, timestamp, body),
            'X-Aegis-Timestamp': timestamp,
        }
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 200
        assert db.get_admin_by_aegis_id(42) is None


class TestPayloadValidation:
    """Malformed payloads are rejected with 400."""

    def test_invalid_json_returns_400(self, webhook_client):
        client, _ = webhook_client
        bad_body = b'not json'
        timestamp = str(int(time.time()))
        headers = {
            'Content-Type': 'application/json',
            'X-Aegis-Event': 'user.verified',
            'X-Aegis-Signature': _sign(WEBHOOK_SECRET, timestamp, bad_body),
            'X-Aegis-Timestamp': timestamp,
        }
        response = client.post(WEBHOOK_PATH, headers=headers, data=bad_body)

        assert response.status_code == 400

    def test_missing_user_id_returns_400(self, webhook_client):
        client, _ = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'email': ALLOWED_EMAIL,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 400

    def test_missing_email_returns_400(self, webhook_client):
        client, _ = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': 42,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 400

    def test_user_id_as_bool_returns_400(self, webhook_client):
        """bool is a subclass of int in Python; reject it explicitly."""
        client, _ = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': True,
            'email': ALLOWED_EMAIL,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 400

    def test_user_id_zero_returns_400(self, webhook_client):
        client, _ = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': 0,
            'email': ALLOWED_EMAIL,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 400

    def test_user_id_negative_returns_400(self, webhook_client):
        client, _ = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': -1,
            'email': ALLOWED_EMAIL,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 400


class TestAllowlistGating:
    """Only emails on the allowlist are provisioned."""

    def test_denied_email_returns_200_but_no_record(self, webhook_client):
        client, db = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': 77,
            'email': DENIED_EMAIL,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 200
        assert db.get_admin_by_aegis_id(77) is None

    def test_empty_allowlist_denies_all(self, webhook_client_no_allowlist):
        client, db = webhook_client_no_allowlist
        headers, body = _build_request()
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 200
        assert db.get_admin_by_aegis_id(42) is None

    def test_allowlist_matching_is_case_insensitive(self, webhook_client):
        client, db = webhook_client
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': 42,
            'email': ALLOWED_EMAIL.upper(),
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 200
        # Provisioning succeeded -- admin record exists
        assert db.get_admin_by_aegis_id(42) is not None


class TestProvisioning:
    """Idempotent provisioning: new creations, sequential replays, race safety."""

    def test_creates_new_admin(self, webhook_client):
        client, db = webhook_client
        headers, body = _build_request()
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 200
        data = response.get_json()
        assert data['received'] is True
        assert 'admin_id' in data

        admin = db.get_admin_by_aegis_id(42)
        assert admin is not None
        assert admin.email == ALLOWED_EMAIL
        assert admin.aegis_user_id == 42

    def test_sequential_replay_is_idempotent(self, webhook_client):
        """Second delivery for the same user is a no-op, same admin_id returned."""
        client, db = webhook_client

        headers, body = _build_request()
        first = client.post(WEBHOOK_PATH, headers=headers, data=body)
        assert first.status_code == 200
        first_admin_id = first.get_json()['admin_id']

        headers2, body2 = _build_request()
        second = client.post(WEBHOOK_PATH, headers=headers2, data=body2)
        assert second.status_code == 200
        assert second.get_json()['admin_id'] == first_admin_id
        assert db.get_admin_by_aegis_id(42).admin_id == first_admin_id

    def test_race_past_fast_path_is_idempotent(self, webhook_client):
        """
        Simulate two concurrent deliveries racing past the fast-path lookup:
        create_admin() is called twice in a row without the Branch-1 guard
        seeing the first result. ON CONFLICT DO NOTHING must make the second
        call return the first's record rather than raising IntegrityError.
        """
        from api_gatekeeper_models import ConsoleAdmin
        _, db = webhook_client

        # Both "racers" build admins with the same aegis_user_id but different
        # timestamps/admin_ids (simulating two request workers).
        a1 = ConsoleAdmin.create_new(aegis_user_id=42, email=ALLOWED_EMAIL)
        a2 = ConsoleAdmin.create_new(aegis_user_id=42, email=ALLOWED_EMAIL)

        first = db.create_admin(a1)
        second = db.create_admin(a2)

        assert first is not None
        assert second is not None
        assert first.admin_id == second.admin_id  # Racer 2 saw the winner's record

        # Exactly one row persisted
        assert db.get_admin_by_aegis_id(42).admin_id == first.admin_id

    def test_email_collision_with_different_aegis_id_returns_500(self, webhook_client):
        """
        If the email is already associated with a different aegis_user_id, the
        create_admin call returns None and the handler surfaces 500 rather
        than silently transferring the identity.
        """
        from api_gatekeeper_models import ConsoleAdmin
        client, db = webhook_client

        # Seed an existing admin with aegis_user_id=100 and the allowed email
        pre = ConsoleAdmin.create_new(aegis_user_id=100, email=ALLOWED_EMAIL)
        created = db.create_admin(pre)
        assert created is not None

        # Webhook for a DIFFERENT aegis_user_id with the same email
        headers, body = _build_request(payload={
            'event_type': 'user.verified',
            'user_id': 999,
            'email': ALLOWED_EMAIL,
            'timestamp': int(time.time()),
        })
        response = client.post(WEBHOOK_PATH, headers=headers, data=body)

        assert response.status_code == 500
        # Original record is untouched
        assert db.get_admin_by_aegis_id(100).email == ALLOWED_EMAIL
        assert db.get_admin_by_aegis_id(999) is None
