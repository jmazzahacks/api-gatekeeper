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

import redis
from src.auth import Authorizer
from src.utils import get_db_connection
from src.database.driver import AuthServiceDB
from src.blueprints import authz_bp, health_bp, metrics_bp
from src.rate_limiter import RateLimiter, RedisBackend
from pythonjsonlogger import jsonlogger

logger = logging.getLogger(__name__)


def _create_rate_limiter(db):
    """
    Create rate limiter with Redis backend.

    If REDIS_HOST is not configured, rate limiting is disabled.
    If REDIS_HOST is configured but connection fails, the application will exit.

    Args:
        db: Database driver instance

    Returns:
        RateLimiter instance or None if Redis not configured
    """
    redis_host = os.environ.get('REDIS_HOST')

    if not redis_host:
        logger.info("Rate limiting disabled (REDIS_HOST not configured)")
        return None

    redis_port = int(os.environ.get('REDIS_PORT', 6379))
    redis_password = os.environ.get('REDIS_PASSWORD')
    redis_db = int(os.environ.get('REDIS_DB', 0))

    redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password,
        db=redis_db,
        decode_responses=True
    )
    redis_client.ping()

    backend = RedisBackend(redis_client)
    logger.info("Rate limiter initialized with Redis backend", extra={
        'redis_host': redis_host,
        'redis_port': redis_port
    })

    return RateLimiter(db, backend)

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


def create_app(db: Optional[AuthServiceDB] = None, rate_limiter=None) -> Flask:
    """
    Create and configure Flask application.

    Args:
        db: Optional database instance (for testing). If None, creates new connection.
        rate_limiter: Optional rate limiter instance (for testing). If None, creates based on env.

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Initialize database connection and authorizer
    if db is None:
        db = get_db_connection(verbose=False)

    # Initialize rate limiter if not provided
    if rate_limiter is None:
        rate_limiter = _create_rate_limiter(db)

    authorizer = Authorizer(db, rate_limiter=rate_limiter)

    # Store in app config for access in route handlers
    app.config['DB'] = db
    app.config['AUTHORIZER'] = authorizer
    app.config['RATE_LIMITER'] = rate_limiter

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
