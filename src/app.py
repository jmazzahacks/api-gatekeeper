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
from pythonjsonlogger import jsonlogger

logger = logging.getLogger(__name__)

# Configure JSON formatter for structured logging
# This ensures extra fields are included in log output
def _configure_json_formatter():
    """Add JSON formatter to root logger to capture extra fields."""
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        timestamp=True
    )

    # Apply JSON formatter to all existing handlers
    for handler in logging.root.handlers:
        handler.setFormatter(formatter)

# Apply JSON formatting (works with both local and Loki modes)
_configure_json_formatter()


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
