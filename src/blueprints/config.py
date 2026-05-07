"""
Public runtime configuration endpoint.

Returns the deployment-specific URLs and branding the frontend needs to
configure its API clients. Loaded by the frontend on first paint so a
single image can be redeployed across tenants without rebuilding.

Public — no auth — values returned are already the same ones baked into
the served HTML/JS in the prior NEXT_PUBLIC_* design.
"""
from flask import Blueprint, current_app, jsonify

config_bp = Blueprint('config', __name__)


@config_bp.route('/api/config', methods=['GET'])
def get_runtime_config():
    response = jsonify({
        'aegisApiUrl': current_app.config.get('AEGIS_API_URL', ''),
        'siteName': current_app.config.get('SITE_NAME', 'gatekeeper'),
        'siteDomain': current_app.config.get('SITE_DOMAIN', ''),
    })
    response.headers['Cache-Control'] = 'public, max-age=60'
    return response, 200
