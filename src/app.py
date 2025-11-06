"""
Flask application for nginx auth_request integration.

This service provides authorization endpoints that nginx calls via auth_request
directive to determine if API requests should be allowed or denied.
"""
import os
import logging
from typing import Optional
from flask import Flask
from src.auth import Authorizer
from src.utils import get_db_connection
from src.database.driver import AuthServiceDB
from src.monitoring import setup_json_logging
from src.blueprints import authz_bp, health_bp, metrics_bp

logger = None  # Will be set up by setup_json_logging()


def create_app(db: Optional[AuthServiceDB] = None) -> Flask:
    """
    Create and configure Flask application.

    Args:
        db: Optional database instance (for testing). If None, creates new connection.

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Set up JSON structured logging
    global logger
    logger = setup_json_logging(app)

    # Initialize database connection and authorizer
    if db is None:
        db = get_db_connection(verbose=False)

    authorizer = Authorizer(db)

    # Store in app config for access in route handlers
    app.config['DB'] = db
    app.config['AUTHORIZER'] = authorizer

    # Register blueprints
    app.register_blueprint(authz_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(metrics_bp)

    return app


# Create default app instance for direct execution
app = create_app()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7843))
    if logger:
        logger.info("Starting API Gatekeeper", extra={
            'port': port,
            'endpoints': ['/authz', '/health', '/metrics']
        })
    app.run(host='0.0.0.0', port=port, debug=False)
