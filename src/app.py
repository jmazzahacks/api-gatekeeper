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
from src.auth import Authorizer, HMACHandler, RedisNonceStorage
from src.utils import get_db_connection
from src.database.driver import AuthServiceDB
from src.blueprints import authz_bp, health_bp, metrics_bp
from src.rate_limiter import RateLimiter, RedisBackend
from pythonjsonlogger import jsonlogger

logger = logging.getLogger(__name__)


def _create_redis_client():
    """
    Create Redis client if configured.

    If REDIS_HOST is not configured, returns None.
    If REDIS_HOST is configured but connection fails, the application will exit.

    Returns:
        Redis client instance or None if not configured
    """
    redis_host = os.environ.get('REDIS_HOST')

    if not redis_host:
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

    logger.info("Redis connection established", extra={
        'redis_host': redis_host,
        'redis_port': redis_port
    })

    return redis_client


def _create_rate_limiter(db, redis_client):
    """
    Create rate limiter with Redis backend.

    Args:
        db: Database driver instance
        redis_client: Redis client instance or None

    Returns:
        RateLimiter instance or None if Redis not available
    """
    if not redis_client:
        logger.info("Rate limiting disabled (Redis not configured)")
        return None

    backend = RedisBackend(redis_client)
    logger.info("Rate limiter initialized with Redis backend")

    return RateLimiter(db, backend)


def _create_hmac_handler(db, redis_client):
    """
    Create HMAC handler with appropriate nonce storage.

    Uses Redis for nonce storage in production (multi-instance safe).
    Falls back to in-memory dict for local development.

    Args:
        db: Database driver instance
        redis_client: Redis client instance or None

    Returns:
        HMACHandler instance
    """
    if redis_client:
        nonce_storage = RedisNonceStorage(redis_client)
        logger.info("HMAC handler initialized with Redis nonce storage (replay protection enabled)")
    else:
        nonce_storage = {}
        logger.warning("HMAC handler using in-memory nonce storage (not safe for multi-instance)")

    return HMACHandler(db, nonce_storage=nonce_storage)

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


def create_app(
    db: Optional[AuthServiceDB] = None,
    redis_client=None,
    rate_limiter=None,
    hmac_handler=None
) -> Flask:
    """
    Create and configure Flask application.

    Args:
        db: Optional database instance (for testing). If None, creates new connection.
        redis_client: Optional Redis client (for testing). If None, creates based on env.
        rate_limiter: Optional rate limiter instance (for testing). If None, creates based on env.
        hmac_handler: Optional HMAC handler instance (for testing). If None, creates based on env.

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Initialize database connection
    if db is None:
        db = get_db_connection(verbose=False)

    # Initialize Redis client if not provided
    if redis_client is None:
        redis_client = _create_redis_client()

    # Initialize rate limiter if not provided
    if rate_limiter is None:
        rate_limiter = _create_rate_limiter(db, redis_client)

    # Initialize HMAC handler with Redis nonce storage if not provided
    if hmac_handler is None:
        hmac_handler = _create_hmac_handler(db, redis_client)

    # Create authorizer with all components
    authorizer = Authorizer(db, hmac_handler=hmac_handler, rate_limiter=rate_limiter)

    # Store in app config for access in route handlers
    app.config['DB'] = db
    app.config['AUTHORIZER'] = authorizer
    app.config['RATE_LIMITER'] = rate_limiter
    app.config['REDIS_CLIENT'] = redis_client

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
