"""Aegis auth proxy endpoints.

Six thin pass-throughs at /api/auth/*. The browser cannot call Aegis directly
for these — Aegis requires the X-Tenant-Api-Key header (server-only) on every
request. We forward the body, attach the key via the AegisClient config, and
return Aegis's response.

Bearer-gated endpoints (/api/auth/me, change-password, logout, refresh,
confirm-email-change) are NOT proxied — the browser calls Aegis directly with
the user's session bearer for those.

The browser-supplied `site_id` field (always sent by byteforge-aegis-client-js)
is intentionally ignored; the proxy uses its own AEGIS_SITE_ID env value when
calling Aegis, so a malicious browser can't redirect the request to a different
site.
"""
import logging
from typing import Any, Callable

from byteforge_aegis_client.exceptions import (
    AegisApiError,
    AegisError,
    AegisNetworkError,
    AegisUnauthorized,
)
from flask import Blueprint, jsonify, request

from src.auth import aegis_tenant_client


logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


def _require_string_field(body: dict, field: str) -> tuple[Any, tuple[Any, int] | None]:
    """Pull a required string field from the body. Returns (value, error_response_or_None)."""
    value = body.get(field)
    if not isinstance(value, str) or not value:
        return None, (jsonify({'error': f'{field} is required'}), 400)
    return value, None


def _aegis_call(fn: Callable, *args, **kwargs):
    """Call an Aegis client method and translate errors into Flask responses."""
    try:
        result = fn(*args, **kwargs)
    except AegisUnauthorized as e:
        return jsonify({'error': str(e) or 'unauthorized'}), 401
    except AegisApiError as e:
        # Propagate Aegis's status code; default to 502 for unexpected 5xx.
        status = e.status_code if 400 <= e.status_code < 500 else 502
        return jsonify({'error': e.message}), status
    except AegisNetworkError as e:
        return jsonify({'error': 'aegis_unavailable', 'detail': str(e)}), 502
    except AegisError as e:
        return jsonify({'error': 'aegis_error', 'detail': str(e)}), 502
    return jsonify(result.to_dict()), 200


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new Aegis user (sends verification email)."""
    body = request.get_json(silent=True) or {}
    email, err = _require_string_field(body, 'email')
    if err:
        return err
    password, err = _require_string_field(body, 'password')
    if err:
        return err
    return _aegis_call(aegis_tenant_client().register, email=email, password=password)


@auth_bp.route('/login', methods=['POST'])
def login():
    """Exchange email + password for a bearer + refresh token."""
    body = request.get_json(silent=True) or {}
    email, err = _require_string_field(body, 'email')
    if err:
        return err
    password, err = _require_string_field(body, 'password')
    if err:
        return err
    return _aegis_call(aegis_tenant_client().login, email=email, password=password)


@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    """Consume a verification token. Sets password if user is admin-created."""
    body = request.get_json(silent=True) or {}
    token, err = _require_string_field(body, 'token')
    if err:
        return err
    password = body.get('password') or None
    return _aegis_call(aegis_tenant_client().verify_email, token=token, password=password)


@auth_bp.route('/check-verification-token', methods=['POST'])
def check_verification_token():
    """Non-consuming probe — returns {password_required, email}."""
    body = request.get_json(silent=True) or {}
    token, err = _require_string_field(body, 'token')
    if err:
        return err
    return _aegis_call(aegis_tenant_client().check_verification_token, token=token)


@auth_bp.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    """Trigger password-reset email."""
    body = request.get_json(silent=True) or {}
    email, err = _require_string_field(body, 'email')
    if err:
        return err
    return _aegis_call(aegis_tenant_client().request_password_reset, email=email)


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Consume a reset token and set a new password."""
    body = request.get_json(silent=True) or {}
    token, err = _require_string_field(body, 'token')
    if err:
        return err
    new_password, err = _require_string_field(body, 'new_password')
    if err:
        return err
    return _aegis_call(
        aegis_tenant_client().reset_password,
        token=token,
        new_password=new_password,
    )
