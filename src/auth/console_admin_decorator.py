"""
Flask decorator that gates endpoints behind a provisioned console admin.

Extracts `Authorization: Bearer <token>`, resolves via AegisAuthenticator,
and attaches the resulting ConsoleAdmin to `flask.g.console_admin`.

Any failure collapses to 401 with a generic error body — callers receive no
signal distinguishing "bad token" from "valid token, user isn't an admin",
which keeps the admin list out of token-enumeration oracles.
"""
import logging
from functools import wraps
from typing import Callable

from flask import current_app, g, jsonify, request

logger = logging.getLogger(__name__)


def _extract_bearer() -> str:
    """Return the bearer token string from Authorization header, or ''."""
    header = request.headers.get('Authorization', '')
    if not header:
        return ''
    scheme, _, token = header.partition(' ')
    if scheme.lower() != 'bearer' or not token:
        return ''
    return token.strip()


def require_console_admin(view_func: Callable) -> Callable:
    """
    Gate a Flask view function behind ConsoleAdmin authentication.

    Usage:
        @bp.route('/api/admin/clients')
        @require_console_admin
        def list_clients():
            admin = g.console_admin
            ...
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        authenticator = current_app.config.get('AEGIS_AUTHENTICATOR')
        if authenticator is None:
            logger.error("AEGIS_AUTHENTICATOR not configured; rejecting admin request")
            return jsonify({'error': 'Admin auth not configured'}), 503

        token = _extract_bearer()
        admin = authenticator.authenticate(token)
        if admin is None:
            return jsonify({'error': 'Unauthorized'}), 401

        g.console_admin = admin
        return view_func(*args, **kwargs)

    return wrapper
