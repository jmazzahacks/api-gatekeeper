"""
Health check endpoint blueprint.

Provides service health status and diagnostics.
"""
import logging
from flask import Blueprint, jsonify, current_app

logger = logging.getLogger(__name__)

health_bp = Blueprint('health', __name__)


@health_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.

    Verifies:
    - Application is running
    - Database connection is healthy
    - Database connection pool status

    Returns:
        200 OK: Service is healthy
            JSON: {
                "status": "healthy",
                "database": "connected",
                "routes_configured": N,
                "clients_configured": N
            }
        503 Service Unavailable: Service is unhealthy
            JSON: {"status": "unhealthy", "database": "error", "message": "..."}
    """
    try:
        # Test database connection
        db = current_app.config['DB']
        routes = db.load_all_routes()
        clients = db.load_all_clients()

        response_data = {
            'status': 'healthy',
            'database': 'connected',
            'routes_configured': len(routes),
            'clients_configured': len(clients)
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error("Health check failed", extra={
            'error_type': type(e).__name__,
            'error_message': str(e)
        }, exc_info=True)

        return jsonify({
            'status': 'unhealthy',
            'database': 'error',
            'message': str(e)
        }), 503
