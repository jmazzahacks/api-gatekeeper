"""Regression coverage for atomic Redis claims and library TTL integration."""
from unittest.mock import Mock, call, patch

import pytest
from byteforge_hmac import DictNonceStorage, ReplayProtector
from redis.exceptions import ConnectionError

from src.auth.hmac_handler import HMACHandler
from src.auth.nonce_storage import RedisNonceStorage
from src.app import _create_hmac_handler


@pytest.mark.parametrize('reply, expected', [(True, True), (None, False)])
def test_claim_uses_one_atomic_redis_command(reply: object, expected: bool) -> None:
    redis = Mock()
    redis.set.return_value = reply
    storage = RedisNonceStorage(redis)

    assert storage.put_if_absent('client:nonce', 1000, 725) is expected
    assert redis.mock_calls == [call.set('hmac_nonce:client:nonce', '1000', nx=True, ex=726)]


def test_custom_prefix() -> None:
    redis = Mock()
    RedisNonceStorage(redis, key_prefix='custom').put_if_absent('nonce', 1000, 1)
    redis.set.assert_called_once_with('custom:nonce', '1000', nx=True, ex=2)


@pytest.mark.parametrize('offset, ttl', [(-299, 1), (0, 300), (300, 600)])
def test_library_passes_remaining_lifetime_and_rejects_replay(offset: int, ttl: int) -> None:
    redis = Mock()
    redis.set.side_effect = [True, None]
    storage = RedisNonceStorage(redis)
    protector = ReplayProtector(storage)
    timestamp = str(1000 + offset)

    with patch('byteforge_hmac.replay_protector.time.time', return_value=1000):
        assert protector.check_and_store('client', 'nonce', timestamp)
        assert not protector.check_and_store('client', 'nonce', timestamp)

    assert protector.storage is storage
    assert redis.mock_calls == [
        call.set('hmac_nonce:client:nonce', timestamp, nx=True, ex=ttl + 1),
        call.set('hmac_nonce:client:nonce', timestamp, nx=True, ex=ttl + 1),
    ]


def test_redis_failure_is_not_treated_as_success() -> None:
    redis = Mock()
    redis.set.side_effect = ConnectionError('unavailable')
    with pytest.raises(ConnectionError):
        RedisNonceStorage(redis).put_if_absent('client:nonce', 1000, 300)


def test_handler_defaults_to_atomic_process_local_storage() -> None:
    handler = HMACHandler(Mock())
    store = handler.authenticator.replay_protector.storage
    assert isinstance(store, DictNonceStorage)
    assert store.put_if_absent('client:nonce', 1000, 300)
    assert not store.put_if_absent('client:nonce', 1000, 300)


@pytest.mark.parametrize('use_redis', [False, True])
def test_application_wires_atomic_storage(use_redis: bool) -> None:
    redis = Mock() if use_redis else None
    handler = _create_hmac_handler(Mock(), redis)
    store = handler.authenticator.replay_protector.storage
    assert isinstance(store, RedisNonceStorage if use_redis else DictNonceStorage)


@pytest.mark.parametrize('redis_error', [False, True])
def test_signed_request_with_redis_storage(redis_error: bool) -> None:
    from api_gatekeeper_models import Client
    from src.auth import RequestSigner

    client = Client.create_new(client_name='nonce-test', shared_secret='test-secret')
    client.client_id = 'c0b4b615-2381-48ff-935b-6c56596abda6'
    db = Mock()
    db.load_client_by_id.return_value = client
    redis = Mock()
    redis.set.side_effect = ConnectionError('unavailable') if redis_error else [True, None]
    handler = HMACHandler(db, nonce_storage=RedisNonceStorage(redis))
    header = RequestSigner(client_id=client.client_id, secret_key='test-secret').sign_post('/test', '{}')

    result = handler.authenticate(header, 'POST', '/test', '{}')
    assert redis.set.called
    if redis_error:
        assert result is None
    else:
        assert result is client
        assert handler.authenticate(header, 'POST', '/test', '{}') is None


@pytest.mark.parametrize('offset', [0, 300])
def test_replay_stays_blocked_through_inclusive_timestamp_boundary(offset: int) -> None:
    """Redis expires at its deadline, while integer timestamps accept equality."""
    from api_gatekeeper_models import Client
    from src.auth import RequestSigner

    clock = [1000.0]
    expires_at: dict[str, float] = {}

    def set_nonce(key: str, value: str, *, nx: bool, ex: int) -> bool | None:
        assert nx is True
        if expires_at.get(key, 0) > clock[0]:
            return None
        expires_at[key] = clock[0] + ex
        return True

    client = Client.create_new(client_name='boundary-test', shared_secret='test-secret')
    client.client_id = 'c0b4b615-2381-48ff-935b-6c56596abda6'
    db = Mock()
    db.load_client_by_id.return_value = client
    redis = Mock()
    redis.set.side_effect = set_nonce
    handler = HMACHandler(db, nonce_storage=RedisNonceStorage(redis))
    with patch('time.time', return_value=1000 + offset):
        header = RequestSigner(client.client_id, 'test-secret').sign_post('/test', '{}')

    with patch('time.time') as now:
        now.return_value = clock[0]
        assert handler.authenticate(header, 'POST', '/test', '{}') is client
        for replay_time in (1300 + offset, 1300.999 + offset, 1301 + offset):
            clock[0] = replay_time
            now.return_value = replay_time
            assert handler.authenticate(header, 'POST', '/test', '{}') is None
