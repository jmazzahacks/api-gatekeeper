"""
Integration tests for @require_console_admin.

Exercises the HTTP layer: header extraction, 401 for unauthenticated, 503
for missing authenticator config, and that g.console_admin is populated
on success.
"""
import time
import pytest
from flask import Blueprint, Flask, g, jsonify

from api_gatekeeper_models import ConsoleAdmin
from byteforge_aegis_client import AegisUnauthorized
from byteforge_aegis_models import User, UserRole

from src.auth import AegisAuthenticator, require_console_admin
import src.auth.aegis_authenticator as aegis_auth_module


AEGIS_URL = 'https://aegis.test'
BEARER_VALID = 'tok_valid'
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


def _build_app(authenticator) -> Flask:
    """Minimal Flask app with a single guarded route used to exercise the decorator."""
    app = Flask(__name__)
    app.config['AEGIS_AUTHENTICATOR'] = authenticator
    app.config['TESTING'] = True

    bp = Blueprint('test_admin', __name__)

    @bp.route('/api/admin/ping', methods=['GET'])
    @require_console_admin
    def ping():
        admin: ConsoleAdmin = g.console_admin
        return jsonify({
            'admin_id': admin.admin_id,
            'email': admin.email,
        })

    app.register_blueprint(bp)
    return app


@pytest.fixture
def provisioned_admin(clean_db) -> ConsoleAdmin:
    admin = ConsoleAdmin.create_new(email=EMAIL, aegis_uuid=AEGIS_UUID)
    return clean_db.create_admin(admin)


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


class TestDecoratorConfig:
    def test_missing_authenticator_returns_503(self, clean_db):
        """If AEGIS_API_URL wasn't configured, guarded routes should refuse to serve."""
        app = _build_app(authenticator=None)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': f'Bearer {BEARER_VALID}'})
        assert resp.status_code == 503


class TestAuthorizationHeader:
    def test_missing_header_returns_401(self, clean_db):
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping')
        assert resp.status_code == 401

    def test_wrong_scheme_returns_401(self, clean_db):
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': f'Token {BEARER_VALID}'})
        assert resp.status_code == 401

    def test_empty_bearer_returns_401(self, clean_db):
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': 'Bearer '})
        assert resp.status_code == 401

    def test_bearer_case_insensitive(self, clean_db, provisioned_admin, fake_me):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': f'BEARER {BEARER_VALID}'})
        assert resp.status_code == 200


class TestAuthenticationOutcomes:
    def test_valid_token_and_provisioned_admin_returns_200(
        self, clean_db, provisioned_admin, fake_me
    ):
        fake_me[BEARER_VALID] = _user()
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': f'Bearer {BEARER_VALID}'})

        assert resp.status_code == 200
        body = resp.get_json()
        assert body['email'] == EMAIL
        assert body['admin_id'] == provisioned_admin.admin_id

    def test_unknown_token_returns_401(self, clean_db, fake_me):
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': 'Bearer bogus'})
        assert resp.status_code == 401

    def test_valid_token_but_not_provisioned_returns_401(self, clean_db, fake_me):
        """Aegis confirms the token but the user isn't in console_admins."""
        fake_me[BEARER_VALID] = _user()  # User exists on Aegis side
        # No provisioned_admin fixture used — console_admins is empty
        auth = AegisAuthenticator(AEGIS_URL, clean_db)
        app = _build_app(auth)
        with app.test_client() as client:
            resp = client.get('/api/admin/ping', headers={'Authorization': f'Bearer {BEARER_VALID}'})
        assert resp.status_code == 401
