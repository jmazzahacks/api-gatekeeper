"""
Admin console HTTP API.

All endpoints are gated by @require_console_admin and prefixed /api/admin.
The frontend console calls these; nginx does NOT proxy them as auth_request
subrequests (they're first-class API endpoints, not authz decisions).
"""
import logging
import time

from api_gatekeeper_models import (
    AuthType,
    ClientSummary,
    HttpMethod,
    MethodAuth,
    PermissionSummary,
    Route,
)
from flask import Blueprint, current_app, g, jsonify, request

from src.auth import require_console_admin

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


def _parse_method_auth(method_str: str, auth_config: object) -> MethodAuth:
    """Validate a single methods[<method>] entry. Raises ValueError on bad input."""
    if not isinstance(auth_config, dict):
        raise ValueError(f'methods[{method_str}] must be an object')

    auth_required = auth_config.get('auth_required')
    if not isinstance(auth_required, bool):
        raise ValueError(f'methods[{method_str}].auth_required must be a boolean')

    raw_auth_type = auth_config.get('auth_type')
    if auth_required:
        if not raw_auth_type:
            raise ValueError(
                f'methods[{method_str}].auth_type is required when auth_required is true'
            )
        try:
            auth_type = AuthType(raw_auth_type)
        except ValueError:
            raise ValueError(f'methods[{method_str}].auth_type must be one of api_key, hmac')
        return MethodAuth(auth_required=True, auth_type=auth_type)

    if raw_auth_type:
        raise ValueError(
            f'methods[{method_str}].auth_type must be null when auth_required is false'
        )
    return MethodAuth(auth_required=False, auth_type=None)


def _parse_route_payload(body: object) -> Route:
    """Validate a route create/update body and return a constructed (unsaved) Route.

    The returned Route has no id and timestamps set via Route.create_new — callers
    constructing an update should override route_id/created_at on the result.

    Raises ValueError with a human-readable message on any validation failure,
    including those raised by Route.__post_init__ (pattern/domain shape).
    """
    if not isinstance(body, dict):
        raise ValueError('request body must be a JSON object')

    route_pattern = body.get('route_pattern')
    if not isinstance(route_pattern, str) or not route_pattern:
        raise ValueError('route_pattern is required')

    domain = body.get('domain')
    if not isinstance(domain, str) or not domain:
        raise ValueError('domain is required')

    service_name = body.get('service_name')
    if not isinstance(service_name, str) or not service_name:
        raise ValueError('service_name is required')

    raw_methods = body.get('methods')
    if not isinstance(raw_methods, dict) or not raw_methods:
        raise ValueError('methods must be a non-empty object')

    methods: dict[HttpMethod, MethodAuth] = {}
    for method_str, auth_config in raw_methods.items():
        try:
            method = HttpMethod(method_str)
        except ValueError:
            raise ValueError(f'unknown http method: {method_str}')
        methods[method] = _parse_method_auth(method_str, auth_config)

    return Route.create_new(
        route_pattern=route_pattern,
        domain=domain,
        service_name=service_name,
        methods=methods,
    )


@admin_bp.route('/routes', methods=['GET'])
@require_console_admin
def list_routes():
    """List all configured routes."""
    db = current_app.config['DB']
    routes = db.load_all_routes()
    return jsonify([route.to_dict() for route in routes]), 200


def _admin_log_extra() -> dict:
    """Build the admin-identity fields for an audit log line."""
    admin = getattr(g, 'console_admin', None)
    return {
        'admin_id': admin.admin_id if admin else None,
        'admin_email': admin.email if admin else None,
    }


@admin_bp.route('/routes', methods=['POST'])
@require_console_admin
def create_route():
    """Create a new route."""
    body = request.get_json(silent=True) or {}
    try:
        route = _parse_route_payload(body)
    except ValueError as e:
        return jsonify({'error': 'invalid_request', 'message': str(e)}), 400

    db = current_app.config['DB']
    db.save_route(route)
    logger.info("Route created", extra={
        **_admin_log_extra(),
        'route_id': route.route_id,
        'route_pattern': route.route_pattern,
        'domain': route.domain,
        'service_name': route.service_name,
        'methods': sorted(m.value for m in route.methods),
    })
    return jsonify(route.to_dict()), 201


@admin_bp.route('/routes/<route_id>', methods=['PUT'])
@require_console_admin
def update_route(route_id: str):
    """Replace a route's configuration. Returns 404 if route_id is unknown."""
    db = current_app.config['DB']
    existing = db.load_route_by_id(route_id)
    if existing is None:
        return jsonify({'error': 'not_found', 'message': 'route not found'}), 404

    body = request.get_json(silent=True) or {}
    try:
        parsed = _parse_route_payload(body)
    except ValueError as e:
        return jsonify({'error': 'invalid_request', 'message': str(e)}), 400

    parsed.route_id = existing.route_id
    parsed.created_at = existing.created_at
    parsed.updated_at = int(time.time())
    db.save_route(parsed)
    logger.info("Route updated", extra={
        **_admin_log_extra(),
        'route_id': parsed.route_id,
        'route_pattern': parsed.route_pattern,
        'domain': parsed.domain,
        'service_name': parsed.service_name,
        'methods': sorted(m.value for m in parsed.methods),
    })
    return jsonify(parsed.to_dict()), 200


@admin_bp.route('/routes/<route_id>', methods=['DELETE'])
@require_console_admin
def delete_route(route_id: str):
    """Delete a route by id. Returns 404 if it didn't exist."""
    db = current_app.config['DB']
    existing = db.load_route_by_id(route_id)
    if existing is None:
        return jsonify({'error': 'not_found', 'message': 'route not found'}), 404

    db.delete_route(route_id)
    logger.info("Route deleted", extra={
        **_admin_log_extra(),
        'route_id': existing.route_id,
        'route_pattern': existing.route_pattern,
        'domain': existing.domain,
        'service_name': existing.service_name,
    })
    return '', 204


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
