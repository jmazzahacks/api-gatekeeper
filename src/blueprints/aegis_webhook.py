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
import uuid as uuid_mod
import psycopg2
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
    aegis_uuid = payload.get('user_uuid')
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

    # user_uuid is Optional during the Aegis phase-1 shim. When present it
    # MUST parse as an RFC-4122 UUID — anything else (empty string, whitespace,
    # int, malformed) is rejected at the API boundary so a garbage payload
    # can't reach psycopg2 and 500 there.
    if aegis_uuid is not None:
        if not isinstance(aegis_uuid, str):
            logger.warning("Aegis webhook has invalid user_uuid type", extra={
                'user_uuid_type': type(aegis_uuid).__name__,
            })
            return jsonify({'error': 'Invalid user_uuid'}), 400
        try:
            # Normalise to lowercase canonical form so DB round-trips match
            aegis_uuid = str(uuid_mod.UUID(aegis_uuid))
        except ValueError:
            logger.warning("Aegis webhook has malformed user_uuid")
            return jsonify({'error': 'Invalid user_uuid'}), 400

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
    # Also inline-backfills aegis_uuid on a pre-shim row when the payload
    # carries one, and warns loudly if the payload disagrees with an
    # already-set stored uuid (a mis-mapping the authenticator would refuse
    # on later — logging it here means the operator sees it upstream).
    existing = db.get_admin_by_aegis_id(aegis_user_id)
    if existing:
        _reconcile_aegis_uuid(db, existing, aegis_user_id, aegis_uuid)
        logger.info("Admin already provisioned; no-op", extra={
            'admin_id': existing.admin_id,
            'email': existing.email,
        })
        return jsonify({
            'received': True,
            'message': 'Admin already provisioned',
            'admin_id': existing.admin_id,
        }), 200

    # Write path: targeted ON CONFLICT (aegis_user_id) inside create_admin
    # makes this safe under concurrent deliveries racing past the fast-path
    # check above. Email- and aegis_uuid-collision paths now raise
    # IntegrityError so the two anomaly classes get distinct 5xx responses
    # and log lines instead of both surfacing as "email collision".
    new_admin = ConsoleAdmin.create_new(
        aegis_user_id=aegis_user_id,
        email=email,
        aegis_uuid=aegis_uuid,
    )
    try:
        result = db.create_admin(new_admin)
    except psycopg2.errors.UniqueViolation as exc:
        constraint = getattr(exc.diag, 'constraint_name', '') or ''
        if 'aegis_uuid' in constraint:
            logger.error(
                "Admin provisioning failed: aegis_uuid already belongs to a different admin row",
                extra={
                    'email': email,
                    'aegis_user_id': aegis_user_id,
                    'aegis_uuid': aegis_uuid,
                    'constraint': constraint,
                },
            )
            return jsonify({'error': 'aegis_uuid collision with existing admin'}), 500
        logger.error(
            "Admin provisioning failed: email already belongs to a different Aegis account",
            extra={
                'email': email,
                'aegis_user_id': aegis_user_id,
                'constraint': constraint,
            },
        )
        return jsonify({'error': 'Email collision with existing admin'}), 500

    if not result:
        # aegis_user_id conflict re-read returned nothing (row deleted between
        # INSERT and re-SELECT?) — genuinely surprising, worth a 500.
        logger.error("Admin provisioning failed: unexpected empty re-read after conflict", extra={
            'email': email,
            'aegis_user_id': aegis_user_id,
        })
        return jsonify({'error': 'Provisioning failed'}), 500

    # Race-repair: if we lost the ON CONFLICT race, `result` is the winner's
    # row. The winner may have inserted with aegis_uuid=NULL (its payload
    # lacked one) while ours carries one — reconcile so the row doesn't stay
    # unbackfilled until another webhook fires.
    _reconcile_aegis_uuid(db, result, aegis_user_id, aegis_uuid)

    logger.info("Provisioned console admin", extra={
        'admin_id': result.admin_id,
        'email': email,
        'aegis_user_id': aegis_user_id,
        'aegis_uuid': aegis_uuid,
    })
    return jsonify({
        'received': True,
        'message': 'Admin provisioned',
        'admin_id': result.admin_id,
    }), 200


def _reconcile_aegis_uuid(db, existing: ConsoleAdmin, aegis_user_id: int, incoming: str) -> None:
    """
    Reconcile the aegis_uuid on an existing row against an incoming webhook
    payload's value:

    - Row has no uuid, payload has one → inline-backfill.
    - Row has a uuid that matches the payload (case-insensitive) → no-op.
    - Row has a uuid that DISAGREES with the payload → WARN loudly. This is
      the same class of anomaly the authenticator's fail-closed guard refuses
      on, and it's cheap to catch here upstream so operators see it before it
      manifests as a login lockout.
    - Payload has no uuid → nothing to do.
    """
    if not incoming:
        return
    if existing.aegis_uuid is None:
        try:
            backfilled = db.backfill_admin_aegis_uuid(aegis_user_id, incoming)
        except psycopg2.errors.UniqueViolation:
            # Target UUID is already held by a different admin row — a data
            # anomaly (Aegis re-mapped, or two admins share the same UUID).
            # Refuse to keep going here; caller can still return 200 for the
            # webhook (the row exists, provisioning is fine), but the anomaly
            # gets an ERROR line rather than silent DB-transaction abort.
            logger.error(
                "Inline-backfill hit aegis_uuid unique conflict",
                extra={
                    'admin_id': existing.admin_id,
                    'aegis_user_id': aegis_user_id,
                    'aegis_uuid': incoming,
                },
            )
            return
        except Exception:
            logger.exception(
                "Inline-backfill of aegis_uuid failed",
                extra={
                    'admin_id': existing.admin_id,
                    'aegis_user_id': aegis_user_id,
                    'aegis_uuid': incoming,
                },
            )
            return
        if backfilled:
            logger.info("Inline-backfilled aegis_uuid on existing admin", extra={
                'admin_id': existing.admin_id,
                'email': existing.email,
                'aegis_user_id': aegis_user_id,
                'aegis_uuid': incoming,
            })
        return
    if existing.aegis_uuid.lower() != incoming:
        logger.warning(
            "Aegis webhook payload's user_uuid disagrees with stored aegis_uuid",
            extra={
                'admin_id': existing.admin_id,
                'aegis_user_id': aegis_user_id,
                'incoming_aegis_uuid': incoming,
                'stored_aegis_uuid': existing.aegis_uuid,
            },
        )
