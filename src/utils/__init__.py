"""
Utility functions for the API authentication service.
"""
from .db_connection import get_db_connection
from .ip_resolver import resolve_client_ip, parse_trusted_forwarder_ips
from .webhook_verifier import verify_aegis_webhook_signature
from .admin_allowlist import parse_admin_allowlist, is_email_allowed
from .cors import parse_cors_allowlist, resolve_allowed_origin

__all__ = [
    'get_db_connection',
    'resolve_client_ip',
    'parse_trusted_forwarder_ips',
    'verify_aegis_webhook_signature',
    'parse_admin_allowlist',
    'is_email_allowed',
    'parse_cors_allowlist',
    'resolve_allowed_origin',
]
