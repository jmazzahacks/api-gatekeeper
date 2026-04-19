"""
Aegis webhook signature verification.

Implements the HMAC-SHA256 scheme described in the Aegis webhook contract:
Aegis signs over the string "{timestamp}.{raw_body}" using the shared secret
and sends the hex digest in the X-Aegis-Signature header prefixed with "sha256=".

The body is treated as opaque bytes (never decoded and re-encoded), matching
industry-standard webhook signing practice (Stripe, Slack, GitHub).
"""
import hmac
import hashlib
import time
from typing import Optional


def verify_aegis_webhook_signature(
    secret: str,
    signature_header: str,
    timestamp_header: str,
    body: bytes,
    tolerance_seconds: int = 300,
    current_time: Optional[int] = None,
) -> bool:
    """
    Verify an Aegis webhook signature.

    Args:
        secret: Shared webhook secret (from Aegis admin)
        signature_header: Value of X-Aegis-Signature header (e.g. "sha256=abc...")
        timestamp_header: Value of X-Aegis-Timestamp header (unix seconds as string)
        body: Raw request body as bytes (do not decode before passing in)
        tolerance_seconds: Max age of the webhook before it's rejected as replay (default 300)
        current_time: Unix timestamp to compare against (for testing); defaults to now

    Returns:
        True if signature is valid and timestamp is within tolerance; False otherwise
    """
    if not signature_header or not signature_header.startswith('sha256='):
        return False

    received_digest = signature_header[len('sha256='):]

    try:
        webhook_time = int(timestamp_header)
    except (TypeError, ValueError):
        return False

    now = current_time if current_time is not None else int(time.time())
    if tolerance_seconds > 0 and abs(now - webhook_time) > tolerance_seconds:
        return False

    message = timestamp_header.encode('utf-8') + b'.' + body
    expected_digest = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_digest, received_digest)
