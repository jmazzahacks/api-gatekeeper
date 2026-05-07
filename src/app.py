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

# Load environment variables from .env file FIRST, so configure_logging() can
# read LOKI_* vars when create_app() runs.
load_dotenv()

from byteforge_loki_logging import configure_logging

import redis
from src.auth import Authorizer, HMACHandler, RedisNonceStorage, AegisAuthenticator
from src.utils import get_db_connection, parse_trusted_forwarder_ips, parse_admin_allowlist
from src.database.driver import AuthServiceDB
from src.blueprints import authz_bp, health_bp, metrics_bp, aegis_webhook_bp, admin_bp, auth_bp, config_bp
from src.rate_limiter import RateLimiter, RedisBackend

logger = logging.getLogger(__name__)

# Sentinel value to distinguish "not provided" from "explicitly None"
_NOT_PROVIDED = object()


def _configure_logging_and_loggers(app: Flask) -> None:
    """
    Initialize byteforge-loki-logging and force Flask / werkzeug / gunicorn
    loggers to propagate to the root logger.

    Must run inside create_app() (not at module level) so SSL state is created
    post-fork in the gunicorn worker process. Also must run after `Flask(__name__)`
    because Flask sets up app.logger during construction and would override an
    earlier propagate flip.
    """
    debug_mode = os.environ.get('DEBUG_LOCAL', 'true').lower() == 'true'
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    configure_logging(
        application_tag='api-gatekeeper',
        debug_local=debug_mode,
        local_level=log_level,
    )

    # Flask's default app.logger has its own StreamHandler with propagate=False.
    # Clear it so that tracebacks from route handlers reach the root logger
    # (and therefore Loki) instead of dead-ending on stdout.
    app.logger.handlers.clear()
    app.logger.propagate = True
    app.logger.setLevel(logging.DEBUG)

    # Same treatment for gunicorn + werkzeug loggers — they also create their
    # own StreamHandler with propagate=False and would bypass Loki otherwise.
    for name in ('werkzeug', 'gunicorn', 'gunicorn.error', 'gunicorn.access'):
        dep_logger = logging.getLogger(name)
        dep_logger.handlers.clear()
        dep_logger.propagate = True


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


def create_app(
    db: Optional[AuthServiceDB] = None,
    redis_client=_NOT_PROVIDED,
    rate_limiter=_NOT_PROVIDED,
    hmac_handler=_NOT_PROVIDED
) -> Flask:
    """
    Create and configure Flask application.

    Args:
        db: Optional database instance (for testing). If None, creates new connection.
        redis_client: Redis client. If not provided, creates based on env. Pass None to disable.
        rate_limiter: Rate limiter instance. If not provided, creates based on env. Pass None to disable.
        hmac_handler: HMAC handler instance. If not provided, creates based on env.

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Wire up Loki logging first — before any helper that might log — so the
    # worker process has its own SSL-capable Loki handler and so Flask's
    # auto-installed app.logger handlers don't swallow route-handler tracebacks.
    _configure_logging_and_loggers(app)

    # Initialize database connection
    if db is None:
        db = get_db_connection(verbose=False)

    # Initialize Redis client if not explicitly provided
    if redis_client is _NOT_PROVIDED:
        redis_client = _create_redis_client()

    # Initialize rate limiter if not explicitly provided
    if rate_limiter is _NOT_PROVIDED:
        rate_limiter = _create_rate_limiter(db, redis_client)

    # Initialize HMAC handler with Redis nonce storage if not explicitly provided
    if hmac_handler is _NOT_PROVIDED:
        hmac_handler = _create_hmac_handler(db, redis_client)

    # Create authorizer with all components
    authorizer = Authorizer(db, hmac_handler=hmac_handler, rate_limiter=rate_limiter)

    # Parse trusted forwarder IPs for client IP resolution
    trusted_ips = parse_trusted_forwarder_ips(
        os.environ.get('TRUSTED_FORWARDER_IPS')
    )
    if trusted_ips:
        logger.info("Trusted forwarder IPs configured", extra={
            'trusted_ips': sorted(trusted_ips)
        })

    # Aegis webhook configuration
    webhook_secret = os.environ.get('AEGIS_WEBHOOK_SECRET')
    admin_allowlist = parse_admin_allowlist(os.environ.get('AEGIS_ADMIN_EMAILS'))

    if not webhook_secret:
        logger.warning(
            "AEGIS_WEBHOOK_SECRET not set; Aegis webhook endpoint will reject all deliveries"
        )
    if not admin_allowlist:
        logger.warning(
            "AEGIS_ADMIN_EMAILS not set; no users will be provisioned as console admins"
        )
    else:
        logger.info("Admin provisioning allowlist configured", extra={
            'allowlist_size': len(admin_allowlist),
        })

    # Aegis bearer-token authentication for the admin console
    aegis_api_url = os.environ.get('AEGIS_API_URL')
    aegis_cache_ttl = int(os.environ.get('AEGIS_AUTH_CACHE_TTL_SECONDS', '60'))
    aegis_authenticator: Optional[AegisAuthenticator] = None
    if aegis_api_url:
        aegis_authenticator = AegisAuthenticator(
            aegis_api_url=aegis_api_url,
            db=db,
            cache_ttl_seconds=aegis_cache_ttl,
        )
        logger.info("Aegis authenticator configured", extra={
            'aegis_api_url': aegis_api_url,
            'cache_ttl_seconds': aegis_cache_ttl,
        })
    else:
        logger.warning(
            "AEGIS_API_URL not set; admin endpoints guarded by @require_console_admin will return 503"
        )

    # Store in app config for access in route handlers
    app.config['DB'] = db
    app.config['AUTHORIZER'] = authorizer
    app.config['RATE_LIMITER'] = rate_limiter
    app.config['REDIS_CLIENT'] = redis_client
    app.config['TRUSTED_FORWARDER_IPS'] = trusted_ips
    app.config['AEGIS_WEBHOOK_SECRET'] = webhook_secret
    app.config['AEGIS_ADMIN_ALLOWLIST'] = admin_allowlist
    app.config['AEGIS_AUTHENTICATOR'] = aegis_authenticator

    # Frontend runtime config — served by /api/config so a single frontend image
    # can be redeployed across tenants without rebuilding (no NEXT_PUBLIC_* baking).
    app.config['AEGIS_API_URL'] = aegis_api_url or ''
    app.config['SITE_NAME'] = os.environ.get('SITE_NAME', 'gatekeeper')
    app.config['SITE_DOMAIN'] = os.environ.get('SITE_DOMAIN', '')

    # Aegis public-auth proxy (login, register, verify-email, password reset).
    # Requires both AEGIS_SITE_ID and AEGIS_TENANT_API_KEY plus AEGIS_API_URL.
    # If any are missing, the /api/auth/* endpoints will 500 on first call —
    # warn at startup so deployment misconfigurations are obvious.
    aegis_site_id = os.environ.get('AEGIS_SITE_ID')
    aegis_tenant_api_key = os.environ.get('AEGIS_TENANT_API_KEY')
    if not aegis_api_url or not aegis_site_id or not aegis_tenant_api_key:
        missing = [name for name, val in (
            ('AEGIS_API_URL', aegis_api_url),
            ('AEGIS_SITE_ID', aegis_site_id),
            ('AEGIS_TENANT_API_KEY', aegis_tenant_api_key),
        ) if not val]
        logger.warning(
            "Aegis auth proxy not fully configured; /api/auth/* endpoints will fail",
            extra={'missing_env': missing},
        )

    # Register blueprints
    app.register_blueprint(authz_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(aegis_webhook_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(config_bp)

    return app


# Create default app instance for direct execution. This runs at import time;
# under gunicorn (no --preload) that's inside the worker process, post-fork.
app = create_app()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7843))
    if logger:
        logger.info("Starting API Gatekeeper", extra={
            'port': port,
            'endpoints': ['/authz', '/health', '/metrics']
        })
    app.run(host='0.0.0.0', port=port, debug=False)
