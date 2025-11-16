"""
Monitoring and observability configuration.

Provides Prometheus metrics and structured logging for the auth service.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time
from functools import wraps
from typing import Callable
import logging
import os
from pythonjsonlogger import jsonlogger


# Prometheus Metrics
AUTH_REQUESTS_TOTAL = Counter(
    'auth_requests_total',
    'Total number of authorization requests',
    ['result', 'route_pattern', 'method']
)

AUTH_DURATION_SECONDS = Histogram(
    'auth_duration_seconds',
    'Authorization request duration in seconds',
    ['route_pattern', 'method'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0)
)

AUTH_ERRORS_TOTAL = Counter(
    'auth_errors_total',
    'Total number of authorization errors',
    ['error_type']
)

DB_CONNECTION_POOL = Gauge(
    'db_connection_pool_connections',
    'Database connection pool status',
    ['state']
)


def setup_json_logging(app):
    """
    Configure JSON structured logging for the application.

    Args:
        app: Flask application instance
    """
    # Create JSON formatter
    log_handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        timestamp=True
    )
    log_handler.setFormatter(formatter)

    # Get log level from environment variable (default: INFO)
    log_level_name = os.environ.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # Configure Flask logger
    app.logger.handlers = []
    app.logger.addHandler(log_handler)
    app.logger.setLevel(log_level)

    # Configure root logger
    logging.root.handlers = []
    logging.root.addHandler(log_handler)
    logging.root.setLevel(log_level)

    return app.logger


def track_auth_request(func: Callable) -> Callable:
    """
    Decorator to track authorization request metrics and timing.

    Measures request duration and increments counters based on result.

    Args:
        func: View function to decorate

    Returns:
        Wrapped function with metrics tracking
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()

        try:
            response = func(*args, **kwargs)
            duration = time.time() - start_time

            # Extract route and method from request context
            from flask import request
            route = request.headers.get('X-Original-URI', 'unknown')
            method = request.headers.get('X-Original-Method', 'unknown')

            # Determine result from response status
            result = 'allowed' if response[1] == 200 else 'denied'

            # Update metrics
            AUTH_REQUESTS_TOTAL.labels(
                result=result,
                route_pattern=route,
                method=method
            ).inc()

            AUTH_DURATION_SECONDS.labels(
                route_pattern=route,
                method=method
            ).observe(duration)

            return response

        except Exception as e:
            duration = time.time() - start_time

            # Track error
            AUTH_ERRORS_TOTAL.labels(
                error_type=type(e).__name__
            ).inc()

            raise

    return wrapper


def get_metrics():
    """
    Generate Prometheus metrics in exposition format.

    Returns:
        Tuple of (metrics_data, content_type)
    """
    return generate_latest(), CONTENT_TYPE_LATEST
