"""
Authorization endpoint blueprint.

Handles nginx auth_request integration for API authorization.
"""
import time
import logging
from typing import Optional
from flask import Blueprint, request, make_response, current_app, Response
from api_gatekeeper_models import HttpMethod, Route
from src.utils import resolve_client_ip, resolve_allowed_origin
from src.monitoring import (
    AUTH_REQUESTS_TOTAL,
    AUTH_DURATION_SECONDS,
    AUTH_ERRORS_TOTAL
)

logger = logging.getLogger(__name__)

authz_bp = Blueprint('authz', __name__)

# Fallback for Access-Control-Allow-Headers when the browser's preflight
# omits Access-Control-Request-Headers. The spec lets us echo the requested
# list verbatim; this default just covers the common JSON+bearer case so
# the response is still useful when no list was sent.
_DEFAULT_ALLOWED_REQUEST_HEADERS = 'Content-Type, Authorization'

# Preflight cache TTL — 1 day. Browsers won't re-issue OPTIONS for the same
# (origin, method, headers) tuple within this window.
_PREFLIGHT_MAX_AGE = '86400'


@authz_bp.route('/authz', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def authorize():
    """
    Nginx auth_request endpoint.

    Nginx passes the original request information via headers:
    - X-Original-URI: The actual request path being authorized
    - X-Original-Method: The HTTP method (GET, POST, etc.)
    - X-Original-Origin: The browser's Origin header (for CORS)
    - Authorization: Client's auth header (if present)
    - Request body: For HMAC validation (POST/PUT/PATCH)

    Returns:
        200 OK: Allow request
            - Sets X-Auth-Client-ID header (client identifier)
            - Sets X-Auth-Client-Name header (client name)
            - Sets Access-Control-Allow-Origin / Vary if origin is allowlisted
        403 Forbidden: Deny request
            - Body contains denial reason
        500 Internal Server Error: System error

    Genuine CORS preflights (OPTIONS carrying both Origin AND
    Access-Control-Request-Method) are short-circuited before authentication:
    gatekeeper looks up the route, checks the Origin against
    CORS_ALLOWED_ORIGINS, checks that the route configures the method the
    preflight is asking about, and returns 200 — otherwise 403. The
    protected upstream is responsible for emitting the Access-Control-*
    response headers — see NGINX_CONF_SKILL.md for the architecture and the
    phase-ordering reason nginx can't relay gatekeeper-built CORS headers
    via auth_request_set.

    A bare OPTIONS (no Origin, or Origin without ACRM) is NOT a preflight
    per spec — it's a non-browser caller such as a healthcheck or curl. It
    falls through to the normal method-policy path so a route that marks
    OPTIONS `auth_required=false` behaves consistently with GET/HEAD. A
    browser preflight from a non-allowlisted origin is still denied — the
    route's OPTIONS method-policy entry does not override the CORS
    allowlist gate for real preflights.
    """
    start_time = time.time()

    try:
        # Extract nginx forwarded headers
        original_uri = request.headers.get('X-Original-URI')
        original_method = request.headers.get('X-Original-Method')
        original_host = request.headers.get('X-Original-Host', '')
        original_origin = request.headers.get('X-Original-Origin', '')

        # Resolve client IP, accounting for trusted forwarders (e.g., upstream
        # servers whose auth subrequests route through Cloudflare)
        trusted_ips = current_app.config.get('TRUSTED_FORWARDER_IPS')
        client_ip = resolve_client_ip(request, trusted_ips)

        # Get user agent for logging (nginx forwards original via X-Original-User-Agent)
        user_agent = request.headers.get('X-Original-User-Agent', 'unknown')

        if not original_uri or not original_method:
            logger.warning("Missing X-Original-URI or X-Original-Method headers")
            return make_response('Missing required headers', 400)

        # Extract domain from host (strip port if present)
        domain = None
        if original_host:
            # Remove port number if present (e.g., example.com:8080 -> example.com)
            domain = original_host.split(':')[0] if ':' in original_host else original_host

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

        # CORS preflight short-circuit — only for GENUINE preflights.
        # Per spec, a preflight always carries both Origin and
        # Access-Control-Request-Method; without either, this is a plain
        # OPTIONS from a non-browser caller (curl, healthcheck) and belongs
        # on the method-policy path, not on the CORS allowlist gate. The
        # short-circuit exists because a real preflight carries no
        # credentials, so running it through auth would always deny unless
        # every route shipped OPTIONS in its allow-list.
        requested_method = request.headers.get('Access-Control-Request-Method', '').strip()
        is_cors_preflight = bool(
            original_method.upper() == 'OPTIONS'
            and original_origin
            and requested_method
        )
        if is_cors_preflight:
            return _handle_cors_preflight(
                path=path,
                domain=domain,
                origin=original_origin,
                requested_method=requested_method,
                requested_headers=request.headers.get('Access-Control-Request-Headers', ''),
                client_ip=client_ip,
                user_agent=user_agent,
                start_time=start_time,
            )

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
            domain=domain,
            headers=headers,
            body=body,
            query_params=query_params if query_params else None
        )

        # Calculate duration
        duration = time.time() - start_time

        # Use matched route ID for metrics labels, or a static placeholder
        # for unmatched routes to prevent cardinality explosion from scanner paths
        route_label = result.matched_route_id or '__unmatched__'

        # Resolve CORS Allow-Origin once; applied to both 200 and 4xx responses
        # so the browser can read the body of authz failures (e.g. show a
        # rate-limit error) instead of dropping it after a successful preflight.
        allowlist = current_app.config.get('CORS_ALLOWED_ORIGINS', frozenset())
        allowed_origin = resolve_allowed_origin(original_origin, allowlist)

        if result.allowed:
            # Update metrics
            AUTH_REQUESTS_TOTAL.labels(
                result='allowed',
                route_pattern=route_label,
                method=method.value
            ).inc()

            AUTH_DURATION_SECONDS.labels(
                route_pattern=route_label,
                method=method.value
            ).observe(duration)

            # Structured logging
            logger.info("Authorization result", extra={
                'client_ip': client_ip,
                'user_agent': user_agent,
                'client_id': result.client_id or 'public',
                'client_name': result.client_name,
                'route': path,
                'domain': domain,
                'route_id': result.matched_route_id,
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

            _apply_cors_actual_headers(response, allowed_origin)
            return response
        else:
            # Update metrics
            AUTH_REQUESTS_TOTAL.labels(
                result='denied',
                route_pattern=route_label,
                method=method.value
            ).inc()

            AUTH_DURATION_SECONDS.labels(
                route_pattern=route_label,
                method=method.value
            ).observe(duration)

            # Structured logging
            logger.warning("Authorization denied", extra={
                'client_ip': client_ip,
                'user_agent': user_agent,
                'client_id': result.client_id,
                'client_name': result.client_name,
                'route': path,
                'domain': domain,
                'route_id': result.matched_route_id,
                'method': original_method,
                'allowed': False,
                'reason': result.reason,
                'duration_ms': round(duration * 1000, 2)
            })

            # Return 429 for rate limit exceeded, 403 for other denials
            status_code = 429 if result.reason == 'rate_limit_exceeded' else 403
            response = make_response(result.reason, status_code)
            _apply_cors_actual_headers(response, allowed_origin)
            return response

    except Exception as e:
        duration = time.time() - start_time

        # Track error
        AUTH_ERRORS_TOTAL.labels(error_type=type(e).__name__).inc()

        # Structured error logging
        error_trusted_ips = current_app.config.get('TRUSTED_FORWARDER_IPS')
        error_client_ip = resolve_client_ip(request, error_trusted_ips)
        error_user_agent = request.headers.get('X-Original-User-Agent', 'unknown')
        logger.error("Authorization error", extra={
            'client_ip': error_client_ip,
            'user_agent': error_user_agent,
            'route': request.headers.get('X-Original-URI', 'unknown'),
            'method': request.headers.get('X-Original-Method', 'unknown'),
            'error_type': type(e).__name__,
            'error_message': str(e),
            'duration_ms': round(duration * 1000, 2)
        }, exc_info=True)

        return make_response('Internal server error', 500)


def _handle_cors_preflight(
    path: str,
    domain: Optional[str],
    origin: str,
    requested_method: str,
    requested_headers: str,
    client_ip: str,
    user_agent: str,
    start_time: float,
) -> Response:
    """
    Build the CORS preflight response.

    Returns 200 when the route exists, the origin is on the allowlist, and
    the route actually configures the method the browser is asking about
    (Access-Control-Request-Method). nginx then forwards the OPTIONS to the
    upstream, which emits the actual Access-Control-* headers. Returns 403
    otherwise, which fails the browser preflight so the real request is
    never sent.

    **This branch deliberately does not authenticate.** A CORS preflight
    carries no credentials by spec, so an authenticated preflight is not a
    thing that exists — gating it on auth would break every browser client
    of a protected route. The gates that DO apply are the origin allowlist
    and the requested-method check above. Consequence to be aware of when
    deploying: a caller who can spoof an allowlisted Origin (i.e. any
    non-browser client — browsers won't let script set Origin) can cause an
    unauthenticated OPTIONS to reach the protected upstream. The upstream
    must therefore treat OPTIONS as safe/idempotent and must not honor
    method-override headers on it. Actual requests are unaffected: they
    carry no preflight headers, so they take the method-policy path and are
    fully authenticated.

    The Access-Control-* headers stamped here are advisory — useful for
    `proxy_pass`-to-/authz consumer setups (see NGINX_CONF_SKILL.md), but
    ignored under the recommended upstream-emits-CORS architecture.
    """
    authorizer = current_app.config['AUTHORIZER']
    allowlist = current_app.config.get('CORS_ALLOWED_ORIGINS', frozenset())

    route: Optional[Route] = authorizer.find_best_route(path, domain)

    duration = time.time() - start_time
    route_label = route.route_id if route else '__unmatched__'

    # Fields common to every outcome; each branch adds its own `reason`.
    log_context = {
        'client_ip': client_ip,
        'user_agent': user_agent,
        'route': path,
        'domain': domain,
        'origin': origin,
        'method': 'OPTIONS',
        'requested_method': requested_method,
        'duration_ms': round(duration * 1000, 2),
    }
    if route is not None:
        log_context['route_id'] = route.route_id

    if route is None:
        _record_preflight_metrics('denied', route_label, duration)
        logger.warning("CORS preflight denied", extra={
            **log_context, 'allowed': False, 'reason': 'no_route_match',
        })
        return make_response('no_route_match', 403)

    allowed_origin = resolve_allowed_origin(origin, allowlist)
    if allowed_origin is None:
        _record_preflight_metrics('denied', route_label, duration)
        logger.warning("CORS preflight denied", extra={
            **log_context, 'allowed': False, 'reason': 'cors_origin_not_allowed',
        })
        return make_response('cors_origin_not_allowed', 403)

    # Approve only a preflight for a method this route actually configures.
    # Without this, any matched route + an allowlisted Origin returned 200
    # for an arbitrary Access-Control-Request-Method, so the preflight said
    # "yes" to methods the actual request would then deny. Checked AFTER the
    # origin gate so a non-allowlisted caller learns nothing about which
    # methods a route exposes.
    try:
        preflight_method = HttpMethod[requested_method.upper()]
    except KeyError:
        preflight_method = None

    if preflight_method is None or route.get_auth_requirements(preflight_method) is None:
        _record_preflight_metrics('denied', route_label, duration)
        logger.warning("CORS preflight denied", extra={
            **log_context, 'allowed': False, 'reason': 'method_not_configured',
        })
        return make_response('method_not_configured', 403)

    allowed_methods = sorted({m.value for m in route.methods.keys()} | {'OPTIONS'})
    response = make_response('', 200)
    response.headers['Access-Control-Allow-Origin'] = allowed_origin
    response.headers['Access-Control-Allow-Methods'] = ', '.join(allowed_methods)
    response.headers['Access-Control-Allow-Headers'] = (
        requested_headers.strip() or _DEFAULT_ALLOWED_REQUEST_HEADERS
    )
    response.headers['Access-Control-Max-Age'] = _PREFLIGHT_MAX_AGE
    response.headers['Vary'] = 'Origin'

    _record_preflight_metrics('allowed', route_label, duration)
    logger.info("CORS preflight allowed", extra={
        **log_context, 'allowed': True, 'reason': 'cors_preflight',
    })
    return response


def _record_preflight_metrics(result: str, route_label: str, duration: float) -> None:
    """
    Record the request-count and duration metrics for a preflight outcome.

    Args:
        result: 'allowed' or 'denied' (the AUTH_REQUESTS_TOTAL label)
        route_label: matched route_id, or '__unmatched__' to keep the label
            cardinality bounded on scanner traffic
        duration: seconds elapsed since the request started
    """
    AUTH_REQUESTS_TOTAL.labels(
        result=result, route_pattern=route_label, method='OPTIONS'
    ).inc()
    AUTH_DURATION_SECONDS.labels(
        route_pattern=route_label, method='OPTIONS'
    ).observe(duration)


def _apply_cors_actual_headers(response: Response, allowed_origin: Optional[str]) -> None:
    """
    Stamp Access-Control-Allow-Origin and Vary onto a non-OPTIONS authz response.

    Without these the browser drops the response body after the preflight
    succeeds — so authz denials wouldn't be readable from the calling app.
    No-op if the origin isn't on the allowlist (or no Origin header was sent).
    """
    if not allowed_origin:
        return
    response.headers['Access-Control-Allow-Origin'] = allowed_origin
    response.headers['Vary'] = 'Origin'
