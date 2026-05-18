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
from .admin_api_key import (
    ADMIN_API_KEY_ENV_VAR,
    ADMIN_API_KEY_HEADER,
    ServiceActor,
    validate_admin_api_key,
)

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
    'ADMIN_API_KEY_ENV_VAR',
    'ADMIN_API_KEY_HEADER',
    'ServiceActor',
    'validate_admin_api_key',
]
