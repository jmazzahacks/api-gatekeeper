"""
Aegis webhook endpoint for provisioning console administrators.

Receives `user.verified` events from Aegis and provisions matching users as
console admins, gated by the AEGIS_ADMIN_EMAILS allowlist.

After Aegis phase-3 (UUID-only contract) the webhook payload keys off
`user_uuid` — the pre-contract `user_id`/`site_id` integer fields are gone.
The handler is idempotent: replaying a webhook for an already-provisioned
user is a no-op (both sequentially and under concurrent delivery, via
ON CONFLICT (aegis_uuid) in the underlying INSERT).
"""
import json
import logging
import uuid as uuid_mod
from typing import Tuple

import psycopg2
from flask import Blueprint, Response, request, jsonify, current_app

from api_gatekeeper_models import ConsoleAdmin
from src.utils import verify_aegis_webhook_signature, is_email_allowed

logger = logging.getLogger(__name__)

aegis_webhook_bp = Blueprint('aegis_webhook', __name__)

WEBHOOK_PATH = '/api/webhooks/aegis'


@aegis_webhook_bp.route(WEBHOOK_PATH, methods=['POST'])
def handle_aegis_webhook() -> Tuple[Response, int]:
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

    body_len = len(raw_body)
    try:
        payload = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        logger.warning("Aegis webhook payload was not valid JSON", extra={
            'body_len': body_len,
            'event_type': event_type,
        })
        return jsonify({'error': 'Invalid JSON payload'}), 400

    raw_uuid = payload.get('user_uuid')
    email = payload.get('email')
    payload_keys = sorted(payload.keys()) if isinstance(payload, dict) else []

    if not isinstance(raw_uuid, str) or not raw_uuid:
        logger.warning("Aegis webhook missing or invalid user_uuid", extra={
            'user_uuid_type': type(raw_uuid).__name__,
            'payload_keys': payload_keys,
        })
        return jsonify({'error': 'Missing or invalid required field: user_uuid'}), 400
    try:
        # Normalise to lowercase canonical form so DB round-trips match.
        aegis_uuid = str(uuid_mod.UUID(raw_uuid))
    except ValueError:
        logger.warning("Aegis webhook has malformed user_uuid", extra={
            'raw_user_uuid': raw_uuid,
            'payload_keys': payload_keys,
        })
        return jsonify({'error': 'Invalid user_uuid'}), 400

    if not isinstance(email, str) or not email:
        logger.warning("Aegis webhook missing or invalid email", extra={
            'email_type': type(email).__name__,
            'aegis_uuid': aegis_uuid,
            'payload_keys': payload_keys,
        })
        return jsonify({'error': 'Missing or invalid required field: email'}), 400

    allowlist = current_app.config.get('AEGIS_ADMIN_ALLOWLIST', frozenset())
    if not is_email_allowed(email, allowlist):
        logger.warning("Aegis webhook: email not on admin allowlist", extra={
            'email': email,
            'aegis_uuid': aegis_uuid,
            'allowlist_configured': len(allowlist) > 0,
        })
        return jsonify({
            'received': True,
            'message': 'Email not authorized for admin provisioning',
        }), 200

    db = current_app.config['DB']

    # Fast path: already provisioned -> idempotent no-op with distinct logging.
    existing = db.get_admin_by_aegis_uuid(aegis_uuid)
    if existing:
        logger.info("Admin already provisioned; no-op", extra={
            'admin_id': existing.admin_id,
            'email': existing.email,
            'aegis_uuid': aegis_uuid,
        })
        return jsonify({
            'received': True,
            'message': 'Admin already provisioned',
            'admin_id': existing.admin_id,
        }), 200

    # Write path: ON CONFLICT (aegis_uuid) inside create_admin makes this
    # safe under concurrent deliveries racing past the fast-path check above.
    # Email collisions raise UniqueViolation so the anomaly gets a distinct
    # 5xx and log line instead of silently succeeding.
    new_admin = ConsoleAdmin.create_new(
        email=email,
        aegis_uuid=aegis_uuid,
    )
    try:
        result = db.create_admin(new_admin)
    except psycopg2.errors.UniqueViolation as exc:
        constraint = getattr(exc.diag, 'constraint_name', '') or ''
        # Look up the existing row that owns this email so operators can see
        # BOTH sides of the collision in a single Loki log line instead of
        # having to pivot to Postgres. Best-effort — a stray failure here
        # must not shadow the primary anomaly report.
        existing_aegis_uuid = None
        existing_admin_id = None
        try:
            existing_by_email = db.get_admin_by_email(email)
            if existing_by_email is not None:
                existing_aegis_uuid = existing_by_email.aegis_uuid
                existing_admin_id = existing_by_email.admin_id
        except Exception:
            logger.exception(
                "Failed to look up existing admin by email while attributing "
                "email-collision anomaly"
            )
        logger.error(
            "Admin provisioning failed: email already belongs to a different Aegis account",
            extra={
                'email': email,
                'aegis_uuid': aegis_uuid,
                'existing_aegis_uuid': existing_aegis_uuid,
                'existing_admin_id': existing_admin_id,
                'constraint': constraint,
            },
        )
        return jsonify({'error': 'Email collision with existing admin'}), 500

    if not result:
        # ON CONFLICT re-read returned nothing (row deleted between INSERT and
        # re-SELECT?) — genuinely surprising, worth a 500.
        logger.error("Admin provisioning failed: unexpected empty re-read after conflict", extra={
            'email': email,
            'aegis_uuid': aegis_uuid,
        })
        return jsonify({'error': 'Provisioning failed'}), 500

    logger.info("Provisioned console admin", extra={
        'admin_id': result.admin_id,
        'email': email,
        'aegis_uuid': aegis_uuid,
    })
    return jsonify({
        'received': True,
        'message': 'Admin provisioned',
        'admin_id': result.admin_id,
    }), 200
