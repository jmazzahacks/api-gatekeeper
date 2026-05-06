"""
Admin console HTTP API.

All endpoints are gated by @require_console_admin and prefixed /api/admin.
The frontend console calls these; nginx does NOT proxy them as auth_request
subrequests (they're first-class API endpoints, not authz decisions).
"""
import logging

from api_gatekeeper_models import ClientSummary, PermissionSummary
from flask import Blueprint, current_app, jsonify

from src.auth import require_console_admin

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


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

    Returns a redacted view (ClientSummary). Full secrets are never surfaced
    through the console; rotation flows return them once at creation.
    """
    db = current_app.config['DB']
    clients = db.load_all_clients()
    return jsonify([ClientSummary.from_client(c).to_dict() for c in clients]), 200


@admin_bp.route('/permissions', methods=['GET'])
@require_console_admin
def list_permissions():
    """List all client→route permissions, joined with display fields."""
    db = current_app.config['DB']
    permissions = db.load_all_permissions()
    clients_by_id = {c.client_id: c for c in db.load_all_clients()}
    routes_by_id = {r.route_id: r for r in db.load_all_routes()}

    rows = [
        PermissionSummary.from_join(
            p,
            clients_by_id[p.client_id],
            routes_by_id[p.route_id],
        ).to_dict()
        for p in permissions
    ]
    return jsonify(rows), 200
