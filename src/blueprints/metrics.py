"""
Prometheus metrics endpoint blueprint.

Exposes metrics for monitoring and alerting.
"""
from flask import Blueprint, Response
from src.monitoring import get_metrics

metrics_bp = Blueprint('metrics', __name__)


@metrics_bp.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """
    Prometheus metrics endpoint.

    Returns Prometheus-formatted metrics:
    - auth_requests_total: Total authorization requests by result/route/method
    - auth_duration_seconds: Authorization latency histogram
    - auth_errors_total: Total errors by type
    - db_connection_pool_connections: Database connection pool status

    Returns:
        200 OK: Metrics in Prometheus exposition format
    """
    metrics_data, content_type = get_metrics()
    return Response(metrics_data, mimetype=content_type)
