"""
Admin console HTTP API.

All endpoints are gated by @require_console_admin and prefixed /api/admin.
The frontend console calls these; nginx does NOT proxy them as auth_request
subrequests (they're first-class API endpoints, not authz decisions).
"""
import logging
import secrets
import time

import psycopg2
from api_gatekeeper_models import (
    AuthType,
    Client,
    ClientPermission,
    ClientStatus,
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

_SECRET_BYTES = 32  # secrets.token_urlsafe(32) -> ~43 char base64url string


def _admin_log_extra() -> dict:
    """Build the admin-identity fields for an audit log line."""
    admin = getattr(g, 'console_admin', None)
    return {
        'admin_id': admin.admin_id if admin else None,
        'admin_email': admin.email if admin else None,
    }


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


def _resolve_credential(name: str, spec: object) -> str | None:
    """Resolve one credential spec from the create-client payload.

    Accepts: None (omit), {'generate': True} (server-side generate), or
    {'value': '<string>'} (use as-is). Anything else raises ValueError.
    """
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise ValueError(f'{name} must be null, {{"generate": true}}, or {{"value": "..."}}')

    if spec.get('generate') is True:
        if 'value' in spec:
            raise ValueError(f'{name} cannot specify both "generate" and "value"')
        return secrets.token_urlsafe(_SECRET_BYTES)

    value = spec.get('value')
    if isinstance(value, str) and value:
        return value

    raise ValueError(f'{name} must be null, {{"generate": true}}, or {{"value": "..."}}')


def _parse_client_create_payload(body: object) -> Client:
    """Validate a POST /api/admin/clients body and return an unsaved Client."""
    if not isinstance(body, dict):
        raise ValueError('request body must be a JSON object')

    client_name = body.get('client_name')
    if not isinstance(client_name, str) or not client_name.strip():
        raise ValueError('client_name is required')

    api_key = _resolve_credential('api_key', body.get('api_key'))
    shared_secret = _resolve_credential('shared_secret', body.get('shared_secret'))

    if api_key is None and shared_secret is None:
        raise ValueError('at least one of api_key or shared_secret must be provided')

    raw_status = body.get('status', 'active')
    try:
        status = ClientStatus(raw_status)
    except ValueError:
        raise ValueError('status must be one of active, suspended, revoked')

    return Client.create_new(
        client_name=client_name.strip(),
        api_key=api_key,
        shared_secret=shared_secret,
        status=status,
    )


def _parse_client_update_payload(body: object) -> tuple[str, ClientStatus]:
    """Validate a PUT /api/admin/clients/<id> body. Returns (name, status)."""
    if not isinstance(body, dict):
        raise ValueError('request body must be a JSON object')

    client_name = body.get('client_name')
    if not isinstance(client_name, str) or not client_name.strip():
        raise ValueError('client_name is required')

    raw_status = body.get('status')
    if raw_status is None:
        raise ValueError('status is required')
    try:
        status = ClientStatus(raw_status)
    except ValueError:
        raise ValueError('status must be one of active, suspended, revoked')

    return client_name.strip(), status


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


@admin_bp.route('/clients', methods=['POST'])
@require_console_admin
def create_client():
    """Create a new client. Returns the full Client (with raw secrets) ONCE.

    The browser is responsible for surfacing the secrets to the user
    immediately and warning them they cannot be retrieved later.
    """
    body = request.get_json(silent=True) or {}
    try:
        client = _parse_client_create_payload(body)
    except ValueError as e:
        return jsonify({'error': 'invalid_request', 'message': str(e)}), 400

    db = current_app.config['DB']
    try:
        db.save_client(client)
    except psycopg2.IntegrityError as e:
        # Schema enforces UNIQUE on api_key and shared_secret. A duplicate
        # custom value collides here; auto-generated values won't.
        constraint = getattr(e.diag, 'constraint_name', '') or ''
        if 'api_key' in constraint:
            field = 'api_key'
        elif 'shared_secret' in constraint:
            field = 'shared_secret'
        else:
            field = 'credential'
        return jsonify({
            'error': 'conflict',
            'message': f'a client with that {field} already exists',
        }), 409
    logger.info("Client created", extra={
        **_admin_log_extra(),
        'client_id': client.client_id,
        'client_name': client.client_name,
        'has_api_key': client.api_key is not None,
        'has_shared_secret': client.shared_secret is not None,
        'status': client.status.value,
    })
    # Return the raw client (one-time secret exposure). Subsequent reads use
    # the redacted ClientSummary projection.
    return jsonify(client.to_dict()), 201


@admin_bp.route('/clients/<client_id>', methods=['PUT'])
@require_console_admin
def update_client(client_id: str):
    """Rename a client and/or change its status. Secrets are immutable here."""
    db = current_app.config['DB']
    existing = db.load_client_by_id(client_id)
    if existing is None:
        return jsonify({'error': 'not_found', 'message': 'client not found'}), 404

    body = request.get_json(silent=True) or {}
    try:
        new_name, new_status = _parse_client_update_payload(body)
    except ValueError as e:
        return jsonify({'error': 'invalid_request', 'message': str(e)}), 400

    existing.client_name = new_name
    existing.status = new_status
    existing.updated_at = int(time.time())
    db.save_client(existing)
    logger.info("Client updated", extra={
        **_admin_log_extra(),
        'client_id': existing.client_id,
        'client_name': existing.client_name,
        'status': existing.status.value,
    })
    return jsonify(ClientSummary.from_client(existing).to_dict()), 200


@admin_bp.route('/clients/<client_id>', methods=['DELETE'])
@require_console_admin
def delete_client(client_id: str):
    """Delete a client. Cascade-removes its permissions."""
    db = current_app.config['DB']
    existing = db.load_client_by_id(client_id)
    if existing is None:
        return jsonify({'error': 'not_found', 'message': 'client not found'}), 404

    db.delete_client(client_id)
    logger.info("Client deleted", extra={
        **_admin_log_extra(),
        'client_id': existing.client_id,
        'client_name': existing.client_name,
    })
    return '', 204


def _parse_allowed_methods(raw: object) -> list[HttpMethod]:
    """Validate an allowed_methods array. Raises ValueError on bad input."""
    if not isinstance(raw, list) or not raw:
        raise ValueError('allowed_methods must be a non-empty array')
    methods: list[HttpMethod] = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ValueError('allowed_methods entries must be strings')
        try:
            methods.append(HttpMethod(entry))
        except ValueError:
            raise ValueError(f'unknown http method: {entry}')
    # De-duplicate while preserving order
    seen: set[HttpMethod] = set()
    deduped: list[HttpMethod] = []
    for m in methods:
        if m not in seen:
            seen.add(m)
            deduped.append(m)
    return deduped


def _parse_permission_create_payload(body: object) -> tuple[str, str, list[HttpMethod]]:
    """Validate POST /api/admin/permissions body. Returns (client_id, route_id, methods)."""
    if not isinstance(body, dict):
        raise ValueError('request body must be a JSON object')

    client_id = body.get('client_id')
    if not isinstance(client_id, str) or not client_id:
        raise ValueError('client_id is required')

    route_id = body.get('route_id')
    if not isinstance(route_id, str) or not route_id:
        raise ValueError('route_id is required')

    methods = _parse_allowed_methods(body.get('allowed_methods'))
    return client_id, route_id, methods


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


@admin_bp.route('/permissions', methods=['POST'])
@require_console_admin
def create_permission():
    """Grant a client permission to access a route with specific methods.

    Returns 409 if a permission for the given (client_id, route_id) pair
    already exists; the caller should PUT to update allowed_methods or DELETE
    + POST to fully replace the row.
    """
    body = request.get_json(silent=True) or {}
    try:
        client_id, route_id, methods = _parse_permission_create_payload(body)
    except ValueError as e:
        return jsonify({'error': 'invalid_request', 'message': str(e)}), 400

    db = current_app.config['DB']
    client = db.load_client_by_id(client_id)
    if client is None:
        return jsonify({'error': 'invalid_request', 'message': 'client_id not found'}), 400
    route = db.load_route_by_id(route_id)
    if route is None:
        return jsonify({'error': 'invalid_request', 'message': 'route_id not found'}), 400

    existing = db.load_permission_by_client_and_route(client_id, route_id)
    if existing is not None:
        return jsonify({
            'error': 'conflict',
            'message': 'a permission for this client and route already exists',
        }), 409

    permission = ClientPermission.create_new(
        client_id=client_id,
        route_id=route_id,
        allowed_methods=methods,
    )
    db.save_permission(permission)
    logger.info("Permission granted", extra={
        **_admin_log_extra(),
        'permission_id': permission.permission_id,
        'client_id': client_id,
        'client_name': client.client_name,
        'route_id': route_id,
        'route_pattern': route.route_pattern,
        'route_domain': route.domain,
        'allowed_methods': sorted(m.value for m in methods),
    })
    summary = PermissionSummary.from_join(permission, client, route).to_dict()
    return jsonify(summary), 201


@admin_bp.route('/permissions/<permission_id>', methods=['PUT'])
@require_console_admin
def update_permission(permission_id: str):
    """Update allowed_methods on an existing permission. client_id and route_id
    are immutable here — to change those, DELETE + POST a new permission.
    """
    db = current_app.config['DB']
    existing = db.load_permission_by_id(permission_id)
    if existing is None:
        return jsonify({'error': 'not_found', 'message': 'permission not found'}), 404

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({'error': 'invalid_request', 'message': 'body must be an object'}), 400
    try:
        methods = _parse_allowed_methods(body.get('allowed_methods'))
    except ValueError as e:
        return jsonify({'error': 'invalid_request', 'message': str(e)}), 400

    existing.allowed_methods = methods
    db.save_permission(existing)

    client = db.load_client_by_id(existing.client_id)
    route = db.load_route_by_id(existing.route_id)
    logger.info("Permission updated", extra={
        **_admin_log_extra(),
        'permission_id': existing.permission_id,
        'client_id': existing.client_id,
        'client_name': client.client_name if client else None,
        'route_id': existing.route_id,
        'route_pattern': route.route_pattern if route else None,
        'allowed_methods': sorted(m.value for m in methods),
    })
    summary = PermissionSummary.from_join(existing, client, route).to_dict()
    return jsonify(summary), 200


@admin_bp.route('/permissions/<permission_id>', methods=['DELETE'])
@require_console_admin
def delete_permission(permission_id: str):
    """Revoke a permission."""
    db = current_app.config['DB']
    existing = db.load_permission_by_id(permission_id)
    if existing is None:
        return jsonify({'error': 'not_found', 'message': 'permission not found'}), 404

    client = db.load_client_by_id(existing.client_id)
    route = db.load_route_by_id(existing.route_id)
    db.delete_permission(permission_id)
    logger.info("Permission revoked", extra={
        **_admin_log_extra(),
        'permission_id': existing.permission_id,
        'client_id': existing.client_id,
        'client_name': client.client_name if client else None,
        'route_id': existing.route_id,
        'route_pattern': route.route_pattern if route else None,
    })
    return '', 204
