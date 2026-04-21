"""
Admin console HTTP API.

All endpoints are gated by @require_console_admin and prefixed /api/admin.
The frontend console calls these; nginx does NOT proxy them as auth_request
subrequests (they're first-class API endpoints, not authz decisions).
"""
import logging

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
