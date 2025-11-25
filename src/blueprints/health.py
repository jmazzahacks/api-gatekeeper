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
    - Redis connection is healthy (if configured)

    Returns:
        200 OK: Service is healthy
            JSON: {
                "status": "healthy",
                "database": "connected",
                "redis": "connected" | "not_configured",
                "routes_configured": N,
                "clients_configured": N
            }
        503 Service Unavailable: Service is unhealthy
            JSON: {"status": "unhealthy", "database": "...", "redis": "...", "message": "..."}
    """
    response_data = {
        'status': 'healthy',
        'database': 'unknown',
        'redis': 'unknown'
    }

    try:
        # Test database connection
        db = current_app.config['DB']
        routes = db.load_all_routes()
        clients = db.load_all_clients()

        response_data['database'] = 'connected'
        response_data['routes_configured'] = len(routes)
        response_data['clients_configured'] = len(clients)

    except Exception as e:
        logger.error("Health check failed - database error", extra={
            'error_type': type(e).__name__,
            'error_message': str(e)
        }, exc_info=True)

        response_data['status'] = 'unhealthy'
        response_data['database'] = 'error'
        response_data['message'] = 'Database connection failed'
        return jsonify(response_data), 503

    # Test Redis connection (if configured)
    redis_client = current_app.config.get('REDIS_CLIENT')

    if redis_client is None:
        response_data['redis'] = 'not_configured'
    else:
        try:
            redis_client.ping()
            response_data['redis'] = 'connected'
        except Exception as e:
            logger.error("Health check failed - Redis error", extra={
                'error_type': type(e).__name__,
                'error_message': str(e)
            }, exc_info=True)

            response_data['status'] = 'unhealthy'
            response_data['redis'] = 'error'
            response_data['message'] = 'Redis connection failed'
            return jsonify(response_data), 503

    return jsonify(response_data), 200
