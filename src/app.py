"""
Flask application for nginx auth_request integration.

This service provides authorization endpoints that nginx calls via auth_request
directive to determine if API requests should be allowed or denied.
"""
import os
import logging
from typing import Optional
from flask import Flask
from dotenv import load_dotenv

# Load environment variables from .env file FIRST
load_dotenv()

# Configure Loki logging with mazza-base
# Must be done before any other imports that might log
from mazza_base import configure_logging

debug_mode = os.environ.get('DEBUG_LOCAL', 'true').lower() == 'true'
log_level = os.environ.get('LOG_LEVEL', 'INFO')
configure_logging(
    application_tag='api-gatekeeper',
    debug_local=debug_mode,
    local_level=log_level
)

from src.auth import Authorizer
from src.utils import get_db_connection
from src.database.driver import AuthServiceDB
from src.blueprints import authz_bp, health_bp, metrics_bp

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
