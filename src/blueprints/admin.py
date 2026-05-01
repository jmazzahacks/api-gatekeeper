"""
Admin console HTTP API.

All endpoints are gated by @require_console_admin and prefixed /api/admin.
The frontend console calls these; nginx does NOT proxy them as auth_request
subrequests (they're first-class API endpoints, not authz decisions).
"""
import logging
from typing import Any

from api_gatekeeper_models import Client
from flask import Blueprint, current_app, jsonify

from src.auth import require_console_admin

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


_MASK_PREFIX = 8
_MASK_SUFFIX = 4


def _mask_api_key(api_key: str) -> str:
    """Show enough of an api_key to identify it without exposing the full value.

    Pattern: first 8 chars + ellipsis + last 4 chars. If the key is short enough
    that prefix+suffix would cover (or exceed) its length — meaning no characters
    would actually be masked — we star the whole thing instead. Real api_keys
    are much longer; this is defensive for truncated/test data.
    """
    if len(api_key) <= _MASK_PREFIX + _MASK_SUFFIX:
        return '*' * len(api_key)
    return f'{api_key[:_MASK_PREFIX]}…{api_key[-_MASK_SUFFIX:]}'


def _client_summary(client: Client) -> dict[str, Any]:
    """Project a Client into the safe shape returned by the list endpoint.

    Excludes shared_secret entirely. Masks api_key. Listing every credential
    in plaintext is unsafe even for an authenticated admin (shoulder-surfing,
    accidental screenshots, browser extensions, log capture).
    """
    return {
        'client_id': client.client_id,
        'client_name': client.client_name,
        'status': client.status.value,
        'api_key_masked': _mask_api_key(client.api_key),
        'created_at': client.created_at,
        'updated_at': client.updated_at,
    }


@admin_bp.route('/routes', methods=['GET'])
@require_console_admin
def list_routes():
    """List all configured routes."""
    db = current_app.config['DB']
    routes = db.load_all_routes()
    return jsonify([route.to_dict() for route in routes]), 200


@admin_bp.route('/clients', methods=['GET'])
@require_console_admin
def list_clients():
    """List all configured clients (credentials).

    Returns a redacted view — see _client_summary. Full secrets are never
    surfaced through the console; rotation flows return them once at creation.
    """
    db = current_app.config['DB']
    clients = db.load_all_clients()
    return jsonify([_client_summary(c) for c in clients]), 200
