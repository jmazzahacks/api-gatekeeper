"""
Tests for the public GET /api/config runtime config endpoint.

This endpoint replaces NEXT_PUBLIC_* build args on the frontend so a single
frontend image can be redeployed across tenants. The shape is the wire
format consumed by lib/runtimeConfig.ts on the frontend.
"""
import pytest

from src.app import create_app
from src.auth import HMACHandler


@pytest.fixture
def client_with_env(clean_db, monkeypatch):
    monkeypatch.setenv('AEGIS_API_URL', 'https://aegis.test.example')
    monkeypatch.setenv('SITE_NAME', 'gatekeeper-test')
    monkeypatch.setenv('SITE_DOMAIN', 'gatekeeper.test.example')

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def client_without_env(clean_db, monkeypatch):
    monkeypatch.delenv('AEGIS_API_URL', raising=False)
    monkeypatch.delenv('SITE_NAME', raising=False)
    monkeypatch.delenv('SITE_DOMAIN', raising=False)

    hmac_handler = HMACHandler(clean_db, nonce_storage={})
    app = create_app(db=clean_db, redis_client=None, hmac_handler=hmac_handler, rate_limiter=None)
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


class TestRuntimeConfig:
    def test_returns_200(self, client_with_env):
        response = client_with_env.get('/api/config')
        assert response.status_code == 200

    def test_no_auth_required(self, client_with_env):
        response = client_with_env.get('/api/config')
        assert response.status_code == 200

    def test_returns_env_values(self, client_with_env):
        response = client_with_env.get('/api/config')
        body = response.get_json()
        assert body == {
            'aegisApiUrl': 'https://aegis.test.example',
            'siteName': 'gatekeeper-test',
            'siteDomain': 'gatekeeper.test.example',
        }

    def test_returns_defaults_when_env_unset(self, client_without_env):
        response = client_without_env.get('/api/config')
        body = response.get_json()
        assert body == {
            'aegisApiUrl': '',
            'siteName': 'gatekeeper',
            'siteDomain': '',
        }

    def test_cache_control_header_set(self, client_with_env):
        response = client_with_env.get('/api/config')
        assert response.headers.get('Cache-Control') == 'public, max-age=60'
