"""
Authorization endpoint blueprint.

Handles nginx auth_request integration for API authorization.
"""
import time
import logging
from flask import Blueprint, request, make_response, current_app
from src.models.route import HttpMethod
from src.monitoring import (
    AUTH_REQUESTS_TOTAL,
    AUTH_DURATION_SECONDS,
    AUTH_ERRORS_TOTAL
)

logger = logging.getLogger(__name__)

authz_bp = Blueprint('authz', __name__)


@authz_bp.route('/authz', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def authorize():
    """
    Nginx auth_request endpoint.

    Nginx passes the original request information via headers:
    - X-Original-URI: The actual request path being authorized
    - X-Original-Method: The HTTP method (GET, POST, etc.)
    - Authorization: Client's auth header (if present)
    - Request body: For HMAC validation (POST/PUT/PATCH)

    Returns:
        200 OK: Allow request
            - Sets X-Auth-Client-ID header (client identifier)
            - Sets X-Auth-Client-Name header (client name)
        403 Forbidden: Deny request
            - Body contains denial reason
        500 Internal Server Error: System error
    """
    start_time = time.time()

    try:
        # Extract nginx forwarded headers
        original_uri = request.headers.get('X-Original-URI')
        original_method = request.headers.get('X-Original-Method')

        if not original_uri or not original_method:
            logger.warning("Missing X-Original-URI or X-Original-Method headers")
            return make_response('Missing required headers', 400)

        # Parse query parameters from URI
        query_params = {}
        if '?' in original_uri:
            path, query_string = original_uri.split('?', 1)
            # Simple query param parsing (nginx may provide this differently)
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
        else:
            path = original_uri

        # Convert method string to HttpMethod enum
        try:
            method = HttpMethod[original_method.upper()]
        except KeyError:
            logger.warning(f"Invalid HTTP method: {original_method}")
            return make_response(f'Invalid method: {original_method}', 400)

        # Get request body for HMAC validation
        body = request.get_data(as_text=True) if request.method in ['POST', 'PUT', 'PATCH'] else ''

        # Convert headers to dict (case-insensitive dict-like object)
        headers = dict(request.headers)

        # Authorize the request
        authorizer = current_app.config['AUTHORIZER']
        result = authorizer.authorize_request(
            path=path,
            method=method,
            headers=headers,
            body=body,
            query_params=query_params if query_params else None
        )

        # Calculate duration
        duration = time.time() - start_time

        if result.allowed:
            # Update metrics
            AUTH_REQUESTS_TOTAL.labels(
                result='allowed',
                route_pattern=result.matched_route_id or path,
                method=original_method
            ).inc()

            AUTH_DURATION_SECONDS.labels(
                route_pattern=result.matched_route_id or path,
                method=original_method
            ).observe(duration)

            # Structured logging
            logger.info("Authorization result", extra={
                'client_id': result.client_id or 'public',
                'route': path,
                'method': original_method,
                'allowed': True,
                'reason': result.reason,
                'duration_ms': round(duration * 1000, 2)
            })

            response = make_response('', 200)

            # Pass client information to upstream service
            if result.client_id:
                response.headers['X-Auth-Client-ID'] = result.client_id
            if result.client_name:
                response.headers['X-Auth-Client-Name'] = result.client_name
            if result.matched_route_id:
                response.headers['X-Auth-Route-ID'] = result.matched_route_id

            return response
        else:
            # Update metrics
            AUTH_REQUESTS_TOTAL.labels(
                result='denied',
                route_pattern=result.matched_route_id or path,
                method=original_method
            ).inc()

            AUTH_DURATION_SECONDS.labels(
                route_pattern=result.matched_route_id or path,
                method=original_method
            ).observe(duration)

            # Structured logging
            logger.warning("Authorization denied", extra={
                'route': path,
                'method': original_method,
                'allowed': False,
                'reason': result.reason,
                'duration_ms': round(duration * 1000, 2)
            })

            return make_response(result.reason, 403)

    except Exception as e:
        duration = time.time() - start_time

        # Track error
        AUTH_ERRORS_TOTAL.labels(error_type=type(e).__name__).inc()

        # Structured error logging
        logger.error("Authorization error", extra={
            'route': request.headers.get('X-Original-URI', 'unknown'),
            'method': request.headers.get('X-Original-Method', 'unknown'),
            'error_type': type(e).__name__,
            'error_message': str(e),
            'duration_ms': round(duration * 1000, 2)
        }, exc_info=True)

        return make_response('Internal server error', 500)
