"""
Aegis webhook endpoint for provisioning console administrators.

Receives `user.verified` events from Aegis and provisions matching users as
console admins, gated by the AEGIS_ADMIN_EMAILS allowlist.

The handler is idempotent: replaying a webhook for an already-provisioned user
is a no-op (both sequentially and under concurrent delivery, via ON CONFLICT
in the underlying INSERT).
"""
import json
import logging
from flask import Blueprint, request, jsonify, current_app

from api_gatekeeper_models import ConsoleAdmin
from src.utils import verify_aegis_webhook_signature, is_email_allowed

logger = logging.getLogger(__name__)

aegis_webhook_bp = Blueprint('aegis_webhook', __name__)

WEBHOOK_PATH = '/api/webhooks/aegis'


@aegis_webhook_bp.route(WEBHOOK_PATH, methods=['POST'])
def handle_aegis_webhook():
    """
    Handle Aegis webhook deliveries.

    Returns 2xx for all cases Aegis shouldn't retry on (including allowlist
    rejections and unhandled event types). Returns 401 for invalid signatures,
    400 for malformed payloads, and 503 if the handler is not configured
    (so Aegis gives up rather than retrying into a misconfiguration).
    """
    webhook_secret = current_app.config.get('AEGIS_WEBHOOK_SECRET')
    if not webhook_secret:
        logger.error("AEGIS_WEBHOOK_SECRET not configured; rejecting webhook")
        return jsonify({'error': 'Webhook handler not configured'}), 503

    signature = request.headers.get('X-Aegis-Signature', '')
    timestamp = request.headers.get('X-Aegis-Timestamp', '')
    raw_body = request.get_data()  # bytes; do not decode before signature check

    if not verify_aegis_webhook_signature(webhook_secret, signature, timestamp, raw_body):
        logger.warning("Invalid Aegis webhook signature", extra={
            'has_signature': bool(signature),
            'has_timestamp': bool(timestamp),
        })
        return jsonify({'error': 'Invalid signature'}), 401

    event_type = request.headers.get('X-Aegis-Event', '')
    if event_type != 'user.verified':
        logger.info("Ignoring non-user.verified Aegis event", extra={
            'event_type': event_type,
        })
        return jsonify({
            'received': True,
            'message': f'Event type {event_type} not processed',
        }), 200

    try:
        payload = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        logger.warning("Aegis webhook payload was not valid JSON")
        return jsonify({'error': 'Invalid JSON payload'}), 400

    aegis_user_id = payload.get('user_id')
    email = payload.get('email')

    # bool is a subclass of int in Python; reject it explicitly. Aegis user_ids
    # are always positive integers.
    if (
        not isinstance(aegis_user_id, int)
        or isinstance(aegis_user_id, bool)
        or aegis_user_id <= 0
        or not isinstance(email, str)
        or not email
    ):
        logger.warning("Aegis webhook missing or invalid required fields", extra={
            'has_user_id': aegis_user_id is not None,
            'has_email': bool(email),
        })
        return jsonify({'error': 'Missing or invalid required fields: user_id, email'}), 400

    allowlist = current_app.config.get('AEGIS_ADMIN_ALLOWLIST', frozenset())
    if not is_email_allowed(email, allowlist):
        logger.warning("Aegis webhook: email not on admin allowlist", extra={
            'email': email,
            'aegis_user_id': aegis_user_id,
            'allowlist_configured': len(allowlist) > 0,
        })
        return jsonify({
            'received': True,
            'message': 'Email not authorized for admin provisioning',
        }), 200

    db = current_app.config['DB']

    # Fast path: already provisioned -> idempotent no-op with distinct logging.
    existing = db.get_admin_by_aegis_id(aegis_user_id)
    if existing:
        logger.info("Admin already provisioned; no-op", extra={
            'admin_id': existing.admin_id,
            'email': existing.email,
        })
        return jsonify({
            'received': True,
            'message': 'Admin already provisioned',
            'admin_id': existing.admin_id,
        }), 200

    # Write path: ON CONFLICT inside create_admin makes this safe under
    # concurrent deliveries racing past the fast-path check above.
    new_admin = ConsoleAdmin.create_new(aegis_user_id=aegis_user_id, email=email)
    result = db.create_admin(new_admin)

    if not result:
        # None means the email conflicted with a DIFFERENT aegis_user_id.
        # That's a data anomaly worth surfacing loudly.
        logger.error("Admin provisioning failed: email already belongs to a different Aegis account", extra={
            'email': email,
            'aegis_user_id': aegis_user_id,
        })
        return jsonify({'error': 'Email collision with existing admin'}), 500

    logger.info("Provisioned console admin", extra={
        'admin_id': result.admin_id,
        'email': email,
        'aegis_user_id': aegis_user_id,
    })
    return jsonify({
        'received': True,
        'message': 'Admin provisioned',
        'admin_id': result.admin_id,
    }), 200
