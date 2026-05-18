"""
Flask decorator that gates endpoints behind admin authentication.

Two auth paths are accepted, in priority order:

1. `X-Gatekeeper-Admin-Key: <env-var-key>` — a long-lived shared secret
   (GATEKEEPER_ADMIN_API_KEY) for service-to-service callers. Permitted
   for read-only requests (GET) only. Sets `g.console_admin` to a
   `ServiceActor` so audit logs distinguish service vs human callers.

2. `Authorization: Bearer <aegis-token>` — an Aegis user token belonging
   to a provisioned ConsoleAdmin. Permitted for any HTTP method. Sets
   `g.console_admin` to the resolved `ConsoleAdmin`.

Any failure collapses to 401 (or 403 for wrong-method on path 1) with a
generic error body — callers receive no signal distinguishing "bad token"
from "valid token, user isn't an admin", which keeps the admin list out
of token-enumeration oracles.
"""
import logging
from functools import wraps
from typing import Callable

from flask import current_app, g, jsonify, request

from .admin_api_key import (
    ADMIN_API_KEY_HEADER,
    ServiceActor,
    validate_admin_api_key,
)

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
    Gate a Flask view function behind admin authentication.

    Usage:
        @bp.route('/api/admin/clients')
        @require_console_admin
        def list_clients():
            admin = g.console_admin  # ConsoleAdmin or ServiceActor
            ...
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        # Path 1: admin API key (service-to-service, GET only).
        # Checked first because it's a cheap env-var compare, no network call.
        admin_key = request.headers.get(ADMIN_API_KEY_HEADER, '')
        if admin_key:
            if not validate_admin_api_key(admin_key):
                return jsonify({'error': 'Unauthorized'}), 401
            # Read-only verbs (GET, HEAD, OPTIONS) allowed. HEAD is GET
            # without a body — Flask routes it to the same view; rejecting
            # it would break health checkers. OPTIONS is the CORS preflight,
            # which clients shouldn't send with this header but if they do
            # the right behavior is to let Flask's automatic handling
            # respond, not to 403 it.
            if request.method not in ('GET', 'HEAD', 'OPTIONS'):
                return jsonify({
                    'error': 'Admin API key permits read-only access; '
                             'write methods require a console-admin Aegis token'
                }), 403
            g.console_admin = ServiceActor(name='admin-api-key')
            return view_func(*args, **kwargs)

        # Path 2: Aegis bearer token (any method, but requires admin role).
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
