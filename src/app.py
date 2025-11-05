"""
Flask application for nginx auth_request integration.

This service provides authorization endpoints that nginx calls via auth_request
directive to determine if API requests should be allowed or denied.
"""
import os
import logging
from typing import Optional
from flask import Flask, request, make_response, jsonify, current_app
from src.auth import Authorizer
from src.models.route import HttpMethod
from src.utils import get_db_connection
from src.database.driver import AuthServiceDB

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(db: Optional[AuthServiceDB] = None) -> Flask:
    """
    Create and configure Flask application.

    Args:
        db: Optional database instance (for testing). If None, creates new connection.

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Initialize database connection and authorizer
    if db is None:
        db = get_db_connection(verbose=False)

    authorizer = Authorizer(db)

    # Store in app config for access in route handlers
    app.config['DB'] = db
    app.config['AUTHORIZER'] = authorizer

    @app.route('/authz', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
    def authz():
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
            logger.info(f"Authorizing: {original_method} {path}")
            authorizer = current_app.config['AUTHORIZER']
            result = authorizer.authorize_request(
                path=path,
                method=method,
                headers=headers,
                body=body,
                query_params=query_params if query_params else None
            )

            if result.allowed:
                logger.info(f"Access allowed: {result.client_id or 'public'} -> {path}")
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
                logger.warning(f"Access denied: {result.reason} -> {path}")
                return make_response(result.reason, 403)

        except Exception as e:
            logger.error(f"Authorization error: {e}", exc_info=True)
            return make_response('Internal server error', 500)

    @app.route('/health', methods=['GET'])
    def health():
        """
        Health check endpoint.

        Verifies:
        - Application is running
        - Database connection is healthy

        Returns:
            200 OK: Service is healthy
                JSON: {"status": "healthy", "database": "connected"}
            503 Service Unavailable: Service is unhealthy
                JSON: {"status": "unhealthy", "database": "error", "message": "..."}
        """
        try:
            # Test database connection
            db = current_app.config['DB']
            routes = db.load_all_routes()

            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'routes_configured': len(routes)
            }), 200

        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return jsonify({
                'status': 'unhealthy',
                'database': 'error',
                'message': str(e)
            }), 503

    return app


# Create default app instance for direct execution
app = create_app()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7843))
    logger.info(f"Starting API Gatekeeper auth service on port {port}")
    logger.info(f"Endpoints: /authz (auth), /health (monitoring)")
    app.run(host='0.0.0.0', port=port, debug=False)
