"""
Authentication and authorization components.
"""
from .models import AuthResult
from .authorizer import Authorizer
from .hmac_handler import HMACHandler, DatabaseSecretProvider
from .api_key_handler import APIKeyHandler
from .request_signer import RequestSigner
from .nonce_storage import RedisNonceStorage
from .aegis_authenticator import AegisAuthenticator
from .aegis_tenant import aegis_tenant_client, reset_tenant_client
from .console_admin_decorator import require_console_admin

__all__ = [
    'AuthResult',
    'Authorizer',
    'HMACHandler',
    'DatabaseSecretProvider',
    'APIKeyHandler',
    'RequestSigner',
    'RedisNonceStorage',
    'AegisAuthenticator',
    'aegis_tenant_client',
    'reset_tenant_client',
    'require_console_admin',
]
