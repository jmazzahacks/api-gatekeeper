"""
Aegis webhook endpoint for console-admin lifecycle events.

Two events are handled:
- `user.verified` — provisions matching users as console admins, gated by the
  AEGIS_ADMIN_EMAILS allowlist. Idempotent on aegis_uuid via ON CONFLICT.
- `user.deleted` — removes the matching console_admins row (keyed on
  aegis_uuid == user_uuid). Idempotent: an unknown uuid is a 200 no-op.
  No allowlist check on deletion — a user removed upstream should be
  deprovisioned regardless of whether they'd be re-provisionable today.

Envelope: Aegis phase-3 (UUID-only contract). Payloads carry `user_uuid`
and `site_uuid`; the pre-contract `user_id`/`site_id` integer keys are
gone. The additive `event_id` field (dedup key, added 2026-07-26) is
tolerated but not currently consumed.
"""
import json
import logging
import uuid as uuid_mod
from typing import List, Optional, Tuple

import psycopg2
from flask import Blueprint, Response, request, jsonify, current_app

from api_gatekeeper_models import ConsoleAdmin
from src.utils import verify_aegis_webhook_signature, is_email_allowed

logger = logging.getLogger(__name__)

aegis_webhook_bp = Blueprint('aegis_webhook', __name__)

WEBHOOK_PATH = '/api/webhooks/aegis'

HANDLED_EVENT_TYPES = frozenset({'user.verified', 'user.deleted'})


@aegis_webhook_bp.route(WEBHOOK_PATH, methods=['POST'])
def handle_aegis_webhook() -> Tuple[Response, int]:
    """
    Handle Aegis webhook deliveries.

    Returns 2xx for all cases Aegis shouldn't retry on (including allowlist
    rejections, unhandled event types, and idempotent no-ops). Returns 401
    for invalid signatures, 400 for malformed payloads, and 503 if the
    handler is not configured (so Aegis gives up rather than retrying
    into a misconfiguration).
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
    if event_type not in HANDLED_EVENT_TYPES:
        logger.info("Ignoring unhandled Aegis event", extra={
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

    raw_uuid = payload.get('user_uuid') if isinstance(payload, dict) else None
    # event_id is Aegis's dedup key (uuidv7, additive on all events as of 2026-07-26).
    # We don't consume it for dedup — outcome-idempotent by design — but we log it
    # so operators can correlate our processing with Aegis's delivery log.
    event_id = payload.get('event_id') if isinstance(payload, dict) else None
    payload_keys = sorted(payload.keys()) if isinstance(payload, dict) else []

    if not isinstance(raw_uuid, str) or not raw_uuid:
        logger.warning("Aegis webhook missing or invalid user_uuid", extra={
            'user_uuid_type': type(raw_uuid).__name__,
            'event_type': event_type,
            'event_id': event_id,
            'payload_keys': payload_keys,
        })
        return jsonify({'error': 'Missing or invalid required field: user_uuid'}), 400
    try:
        # Normalise to lowercase canonical form so DB round-trips match.
        aegis_uuid = str(uuid_mod.UUID(raw_uuid))
    except ValueError:
        logger.warning("Aegis webhook has malformed user_uuid", extra={
            'raw_user_uuid': raw_uuid,
            'event_type': event_type,
            'event_id': event_id,
            'payload_keys': payload_keys,
        })
        return jsonify({'error': 'Invalid user_uuid'}), 400

    db = current_app.config['DB']

    if event_type == 'user.verified':
        return _handle_user_verified(payload, aegis_uuid, event_id, payload_keys, db)
    elif event_type == 'user.deleted':
        return _handle_user_deleted(aegis_uuid, event_id, db)
    # Unreachable — HANDLED_EVENT_TYPES gates entry above. Defensive 200 in
    # case someone adds a type to the set without wiring a branch here.
    logger.error("Aegis webhook: handled event_type has no branch wired", extra={
        'event_type': event_type,
        'event_id': event_id,
    })
    return jsonify({
        'received': True,
        'message': f'Event type {event_type} recognised but not routed',
    }), 200


def _handle_user_verified(
    payload: dict,
    aegis_uuid: str,
    event_id: Optional[str],
    payload_keys: List[str],
    db,
) -> Tuple[Response, int]:
    """Provision (or replay-noop) a console admin for a verified Aegis user."""
    email = payload.get('email')

    if not isinstance(email, str) or not email:
        logger.warning("Aegis webhook missing or invalid email", extra={
            'email_type': type(email).__name__,
            'aegis_uuid': aegis_uuid,
            'event_id': event_id,
            'payload_keys': payload_keys,
        })
        return jsonify({'error': 'Missing or invalid required field: email'}), 400

    allowlist = current_app.config.get('AEGIS_ADMIN_ALLOWLIST', frozenset())
    if not is_email_allowed(email, allowlist):
        logger.warning("Aegis webhook: email not on admin allowlist", extra={
            'email': email,
            'aegis_uuid': aegis_uuid,
            'event_id': event_id,
            'allowlist_configured': len(allowlist) > 0,
        })
        return jsonify({
            'received': True,
            'message': 'Email not authorized for admin provisioning',
        }), 200

    # Fast path: already provisioned -> idempotent no-op with distinct logging.
    existing = db.get_admin_by_aegis_uuid(aegis_uuid)
    if existing:
        logger.info("Admin already provisioned; no-op", extra={
            'admin_id': existing.admin_id,
            'email': existing.email,
            'aegis_uuid': aegis_uuid,
            'event_id': event_id,
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
                'event_id': event_id,
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
            'event_id': event_id,
        })
        return jsonify({'error': 'Provisioning failed'}), 500

    logger.info("Provisioned console admin", extra={
        'admin_id': result.admin_id,
        'email': email,
        'aegis_uuid': aegis_uuid,
        'event_id': event_id,
    })
    return jsonify({
        'received': True,
        'message': 'Admin provisioned',
        'admin_id': result.admin_id,
    }), 200


def _handle_user_deleted(
    aegis_uuid: str,
    event_id: Optional[str],
    db,
) -> Tuple[Response, int]:
    """
    Remove the console_admins row for a deleted Aegis user.

    Idempotent: an unknown aegis_uuid returns 200 no-op (retry-safe).
    No allowlist check — a user removed upstream should be deprovisioned
    regardless of whether they'd currently qualify for re-provisioning.
    """
    # Fast path: look up first so we can log the pre-existing admin_id/email
    # in the resolution line. Also lets us distinguish "actually removed"
    # from "already gone" in Loki.
    existing = db.get_admin_by_aegis_uuid(aegis_uuid)
    if not existing:
        logger.info("Aegis user.deleted for unknown aegis_uuid; no-op", extra={
            'aegis_uuid': aegis_uuid,
            'event_id': event_id,
        })
        return jsonify({
            'received': True,
            'message': 'No matching admin to remove',
        }), 200

    deleted = db.delete_admin_by_aegis_uuid(aegis_uuid)
    if not deleted:
        # Row disappeared between our fast-path SELECT and the DELETE. Could
        # be a concurrent delivery, but also a manual admin script or any
        # other external DELETE. Still an idempotent outcome — log the race
        # neutrally so operators don't chase a phantom duplicate delivery.
        logger.info("Aegis user.deleted found row missing between SELECT and DELETE; no-op", extra={
            'aegis_uuid': aegis_uuid,
            'event_id': event_id,
            'expected_admin_id': existing.admin_id,
        })
        return jsonify({
            'received': True,
            'message': 'Admin already removed',
        }), 200

    logger.info("Deprovisioned console admin per Aegis user.deleted", extra={
        'admin_id': existing.admin_id,
        'email': existing.email,
        'aegis_uuid': aegis_uuid,
        'event_id': event_id,
    })
    return jsonify({
        'received': True,
        'message': 'Admin removed',
        'admin_id': existing.admin_id,
    }), 200
