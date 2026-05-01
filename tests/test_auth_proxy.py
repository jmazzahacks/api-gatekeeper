"""
Integration tests for the /api/auth/* Aegis proxy endpoints.

Verifies request validation, AegisClient invocation with correct args,
response serialization, and Aegis error translation. The tenant client
is patched out — we don't hit the real Aegis here.
"""
import time
from unittest.mock import MagicMock

import pytest
from byteforge_aegis_client.exceptions import (
    AegisApiError,
    AegisNetworkError,
    AegisUnauthorized,
)
from byteforge_aegis_models import (
    AuthToken,
    LoginResult,
    MessageResponse,
    RefreshToken,
    User,
    UserRole,
    VerificationResult,
    VerificationTokenStatus,
)

from src.app import create_app
from src.auth import HMACHandler
import src.blueprints.auth as auth_module


@pytest.fixture
def fake_tenant_client(monkeypatch):
    """Replace aegis_tenant_client() with a MagicMock so tests can stub each method."""
    mock_client = MagicMock()

    def fake_factory() -> MagicMock:
        return mock_client

    monkeypatch.setattr(auth_module, 'aegis_tenant_client', fake_factory)
    return mock_client


@pytest.fixture
def auth_client(clean_db, fake_tenant_client):
    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as flask_client:
        yield flask_client, fake_tenant_client


def _user(user_id: int = 42, email: str = 'user@example.com') -> User:
    now = int(time.time())
    return User(
        id=user_id,
        site_id=1,
        email=email,
        is_verified=True,
        role=UserRole.USER,
        created_at=now,
        updated_at=now,
    )


def _login_result(user_id: int = 42) -> LoginResult:
    now = int(time.time())
    return LoginResult(
        auth_token=AuthToken(
            token='auth-tok',
            user_id=user_id,
            site_id=1,
            expires_at=now + 3600,
            created_at=now,
        ),
        refresh_token=RefreshToken(
            token='refresh-tok',
            user_id=user_id,
            site_id=1,
            expires_at=now + 7 * 86400,
        ),
    )


# ---------------------------------------------------------------------------
# /register
# ---------------------------------------------------------------------------

class TestRegister:
    def test_happy_path(self, auth_client):
        client, mock = auth_client
        mock.register.return_value = MessageResponse(message='Registration initiated')

        response = client.post('/api/auth/register', json={
            'email': 'new@example.com',
            'password': 'secretpw123',
        })

        assert response.status_code == 200
        assert response.get_json() == {'message': 'Registration initiated'}
        mock.register.assert_called_once_with(email='new@example.com', password='secretpw123')

    def test_ignores_browser_supplied_site_id(self, auth_client):
        """The browser-side AuthClient always sends site_id; the proxy must not forward it."""
        client, mock = auth_client
        mock.register.return_value = MessageResponse(message='ok')

        response = client.post('/api/auth/register', json={
            'site_id': 999,
            'email': 'new@example.com',
            'password': 'secretpw123',
        })

        assert response.status_code == 200
        # site_id from body must not appear in kwargs to the AegisClient.
        _, kwargs = mock.register.call_args
        assert 'site_id' not in kwargs

    def test_missing_email_returns_400(self, auth_client):
        client, _ = auth_client
        response = client.post('/api/auth/register', json={'password': 'secretpw123'})
        assert response.status_code == 400

    def test_missing_password_returns_400(self, auth_client):
        client, _ = auth_client
        response = client.post('/api/auth/register', json={'email': 'a@b.com'})
        assert response.status_code == 400

    def test_aegis_api_error_translates_status(self, auth_client):
        client, mock = auth_client
        mock.register.side_effect = AegisApiError(409, 'Email already registered')

        response = client.post('/api/auth/register', json={
            'email': 'taken@example.com',
            'password': 'secretpw123',
        })
        assert response.status_code == 409
        assert response.get_json()['error'] == 'Email already registered'


# ---------------------------------------------------------------------------
# /login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_happy_path_returns_tokens(self, auth_client):
        client, mock = auth_client
        mock.login.return_value = _login_result(user_id=42)

        response = client.post('/api/auth/login', json={
            'email': 'user@example.com',
            'password': 'pw123',
        })

        assert response.status_code == 200
        body = response.get_json()
        assert body['auth_token']['token'] == 'auth-tok'
        assert body['auth_token']['user_id'] == 42
        assert body['refresh_token']['token'] == 'refresh-tok'
        mock.login.assert_called_once_with(email='user@example.com', password='pw123')

    def test_invalid_credentials_returns_401(self, auth_client):
        client, mock = auth_client
        mock.login.side_effect = AegisUnauthorized('Invalid credentials')

        response = client.post('/api/auth/login', json={
            'email': 'user@example.com',
            'password': 'wrong',
        })
        assert response.status_code == 401

    def test_aegis_unreachable_returns_502(self, auth_client):
        client, mock = auth_client
        mock.login.side_effect = AegisNetworkError('connection refused')

        response = client.post('/api/auth/login', json={
            'email': 'user@example.com',
            'password': 'pw',
        })
        assert response.status_code == 502
        assert response.get_json()['error'] == 'aegis_unavailable'


# ---------------------------------------------------------------------------
# /verify-email
# ---------------------------------------------------------------------------

class TestVerifyEmail:
    def test_happy_path_no_password(self, auth_client):
        client, mock = auth_client
        mock.verify_email.return_value = VerificationResult(
            user=_user(),
            redirect_url='https://example.com/welcome',
        )

        response = client.post('/api/auth/verify-email', json={'token': 'verify-tok'})

        assert response.status_code == 200
        body = response.get_json()
        assert body['user']['email'] == 'user@example.com'
        assert body['redirect_url'] == 'https://example.com/welcome'
        mock.verify_email.assert_called_once_with(token='verify-tok', password=None)

    def test_happy_path_with_password(self, auth_client):
        client, mock = auth_client
        mock.verify_email.return_value = VerificationResult(
            user=_user(),
            redirect_url='https://example.com/welcome',
        )

        client.post('/api/auth/verify-email', json={
            'token': 'verify-tok',
            'password': 'newpw',
        })
        mock.verify_email.assert_called_once_with(token='verify-tok', password='newpw')

    def test_missing_token_returns_400(self, auth_client):
        client, _ = auth_client
        response = client.post('/api/auth/verify-email', json={})
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# /check-verification-token
# ---------------------------------------------------------------------------

class TestCheckVerificationToken:
    def test_happy_path(self, auth_client):
        client, mock = auth_client
        mock.check_verification_token.return_value = VerificationTokenStatus(
            password_required=True,
            email='admin@example.com',
        )

        response = client.post('/api/auth/check-verification-token', json={'token': 'tok'})

        assert response.status_code == 200
        body = response.get_json()
        assert body['password_required'] is True
        assert body['email'] == 'admin@example.com'

    def test_invalid_token_returns_400_from_aegis(self, auth_client):
        client, mock = auth_client
        mock.check_verification_token.side_effect = AegisApiError(400, 'Invalid token')

        response = client.post('/api/auth/check-verification-token', json={'token': 'bogus'})
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# /request-password-reset
# ---------------------------------------------------------------------------

class TestRequestPasswordReset:
    def test_happy_path(self, auth_client):
        client, mock = auth_client
        mock.request_password_reset.return_value = MessageResponse(message='If the email exists, a reset link was sent.')

        response = client.post('/api/auth/request-password-reset', json={'email': 'user@example.com'})

        assert response.status_code == 200
        mock.request_password_reset.assert_called_once_with(email='user@example.com')

    def test_missing_email_returns_400(self, auth_client):
        client, _ = auth_client
        response = client.post('/api/auth/request-password-reset', json={})
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# /reset-password
# ---------------------------------------------------------------------------

class TestResetPassword:
    def test_happy_path(self, auth_client):
        client, mock = auth_client
        mock.reset_password.return_value = _user()

        response = client.post('/api/auth/reset-password', json={
            'token': 'reset-tok',
            'new_password': 'brandnew',
        })

        assert response.status_code == 200
        mock.reset_password.assert_called_once_with(token='reset-tok', new_password='brandnew')

    def test_missing_new_password_returns_400(self, auth_client):
        client, _ = auth_client
        response = client.post('/api/auth/reset-password', json={'token': 'reset-tok'})
        assert response.status_code == 400

    def test_expired_token_propagates_400(self, auth_client):
        client, mock = auth_client
        mock.reset_password.side_effect = AegisApiError(400, 'Token expired')

        response = client.post('/api/auth/reset-password', json={
            'token': 'old',
            'new_password': 'pw',
        })
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Token expired'
