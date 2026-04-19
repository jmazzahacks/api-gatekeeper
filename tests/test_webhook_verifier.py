"""
Tests for Aegis webhook signature verification.
"""
import hmac
import hashlib
import time

from src.utils import verify_aegis_webhook_signature


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    """Helper: produce a valid X-Aegis-Signature value for given inputs."""
    message = timestamp.encode('utf-8') + b'.' + body
    digest = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class TestVerifyAegisWebhookSignature:
    """Tests for verify_aegis_webhook_signature."""

    def test_valid_signature_returns_true(self):
        secret = 'test_secret'
        body = b'{"event_type":"user.verified","user_id":42}'
        timestamp = str(int(time.time()))
        signature = _sign(secret, timestamp, body)

        assert verify_aegis_webhook_signature(secret, signature, timestamp, body) is True

    def test_tampered_body_returns_false(self):
        secret = 'test_secret'
        body = b'{"event_type":"user.verified","user_id":42}'
        timestamp = str(int(time.time()))
        signature = _sign(secret, timestamp, body)

        tampered_body = b'{"event_type":"user.verified","user_id":99}'
        assert verify_aegis_webhook_signature(secret, signature, timestamp, tampered_body) is False

    def test_wrong_secret_returns_false(self):
        body = b'{"event_type":"user.verified","user_id":42}'
        timestamp = str(int(time.time()))
        signature = _sign('correct_secret', timestamp, body)

        assert verify_aegis_webhook_signature('wrong_secret', signature, timestamp, body) is False

    def test_missing_sha256_prefix_returns_false(self):
        secret = 'test_secret'
        body = b'{}'
        timestamp = str(int(time.time()))
        signature = _sign(secret, timestamp, body)
        bare_digest = signature[len('sha256='):]

        assert verify_aegis_webhook_signature(secret, bare_digest, timestamp, body) is False

    def test_empty_signature_returns_false(self):
        assert verify_aegis_webhook_signature('secret', '', str(int(time.time())), b'{}') is False

    def test_non_numeric_timestamp_returns_false(self):
        assert verify_aegis_webhook_signature('secret', 'sha256=abc', 'not_a_number', b'{}') is False

    def test_replay_outside_tolerance_returns_false(self):
        secret = 'test_secret'
        body = b'{}'
        now = 1_700_000_000
        old_timestamp = str(now - 400)  # 400s old, beyond default 300s tolerance
        signature = _sign(secret, old_timestamp, body)

        assert verify_aegis_webhook_signature(
            secret, signature, old_timestamp, body, current_time=now
        ) is False

    def test_replay_inside_tolerance_returns_true(self):
        secret = 'test_secret'
        body = b'{}'
        now = 1_700_000_000
        recent_timestamp = str(now - 100)  # 100s old, within default 300s tolerance
        signature = _sign(secret, recent_timestamp, body)

        assert verify_aegis_webhook_signature(
            secret, signature, recent_timestamp, body, current_time=now
        ) is True

    def test_future_timestamp_outside_tolerance_returns_false(self):
        secret = 'test_secret'
        body = b'{}'
        now = 1_700_000_000
        future_timestamp = str(now + 400)
        signature = _sign(secret, future_timestamp, body)

        assert verify_aegis_webhook_signature(
            secret, signature, future_timestamp, body, current_time=now
        ) is False

    def test_tolerance_zero_disables_replay_check(self):
        secret = 'test_secret'
        body = b'{}'
        now = 1_700_000_000
        old_timestamp = str(now - 99_999)
        signature = _sign(secret, old_timestamp, body)

        assert verify_aegis_webhook_signature(
            secret, signature, old_timestamp, body,
            tolerance_seconds=0, current_time=now,
        ) is True

    def test_body_with_utf8_bytes_is_signed_correctly(self):
        secret = 'test_secret'
        # Non-ASCII bytes that survive unchanged through the byte-oriented path
        body = '{"email":"用户@example.com"}'.encode('utf-8')
        timestamp = str(int(time.time()))
        signature = _sign(secret, timestamp, body)

        assert verify_aegis_webhook_signature(secret, signature, timestamp, body) is True

    def test_empty_body_with_valid_signature_returns_true(self):
        secret = 'test_secret'
        body = b''
        timestamp = str(int(time.time()))
        signature = _sign(secret, timestamp, body)

        assert verify_aegis_webhook_signature(secret, signature, timestamp, body) is True
