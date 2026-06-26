"""
Dead-connection resilience tests for AuthServiceDB.

Pure unit tests — the pool is mocked, no live Postgres needed. Cover:

  - happy path: alive conn yielded and recycled WITHOUT close=True
  - dead conn on checkout: discard with close=True, retry, recover
  - pool of corpses: every putconn called with close=True; raise after
    MAX_HEALTH_RETRIES with the underlying psycopg2 error chained
  - mid-flight dead conn (rollback also fails): discard with close=True
  - mid-flight app exception on healthy conn (SerializationFailure,
    ValueError, etc.): recycle WITHOUT close=True — this is the fix for
    OperationalError being too broad
  - mid-flight app exception on silently-dead conn: detected via rollback
    failure, discard with close=True
  - non-dead exception during checkout (PoolError from getconn):
    propagate without retry
  - _check_alive: cursor closed and conn rolled back
  - active-connection counter returns to 0 after every path
  - _is_dead_conn_error classifier behaves correctly on all branches
"""
from typing import List
from unittest.mock import MagicMock, call

import psycopg2
import psycopg2.pool
import pytest

from src.database.driver import MAX_HEALTH_RETRIES, AuthServiceDB


def _make_db_with_mocked_pool(connections: List[MagicMock]) -> AuthServiceDB:
    """Build an AuthServiceDB whose pool yields the given pre-built mock conns."""
    db = AuthServiceDB.__new__(AuthServiceDB)  # skip __init__'s real ThreadedConnectionPool
    db.pool = MagicMock()
    db.pool.getconn.side_effect = list(connections)
    db._active_connections = 0
    db._max_conn = 10
    return db


def _alive_conn() -> MagicMock:
    """Mock conn whose pre-ping (SELECT 1) succeeds and reports closed=0."""
    conn = MagicMock()
    conn.cursor.return_value.fetchone.return_value = (1,)
    conn.closed = 0
    return conn


def _dead_conn() -> MagicMock:
    """Mock conn whose pre-ping raises OperationalError and reports closed=2."""
    conn = MagicMock()
    conn.cursor.return_value.execute.side_effect = psycopg2.OperationalError("dead")
    conn.closed = 2
    return conn


# ----- Happy path -----


def test_happy_path_returns_alive_conn_without_close() -> None:
    """No failures: conn is yielded, recycled with close=False, counter balances."""
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([alive])

    with db._get_connection() as conn:
        assert conn is alive

    db.pool.getconn.assert_called_once()
    db.pool.putconn.assert_called_once_with(alive, close=False)
    assert db._active_connections == 0


def test_check_alive_closes_cursor_and_rolls_back() -> None:
    """Pre-ping must close the cursor and rollback the conn (clean tx state)."""
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([alive])

    with db._get_connection():
        pass

    alive.cursor.return_value.execute.assert_called_with("SELECT 1")
    alive.cursor.return_value.close.assert_called()
    alive.rollback.assert_called()


# ----- Retry on dead conn -----


@pytest.mark.parametrize(
    "exc_cls", [psycopg2.OperationalError, psycopg2.InterfaceError]
)
def test_dead_conn_on_checkout_retries_and_recovers(exc_cls: type) -> None:
    """Dead conn discarded with close=True; alive conn recycled with close=False."""
    dead = MagicMock()
    dead.cursor.return_value.execute.side_effect = exc_cls("dead")
    dead.closed = 2
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([dead, alive])

    with db._get_connection() as conn:
        assert conn is alive

    # Verify BOTH conns went back: dead with close=True, alive with close=False.
    assert db.pool.putconn.call_args_list == [
        call(dead, close=True),
        call(alive, close=False),
    ]
    assert db._active_connections == 0


def test_pool_full_of_corpses_raises_after_max_retries_with_close_true() -> None:
    """Every dead conn must be discarded with close=True so the pool refills."""
    corpses = [_dead_conn() for _ in range(MAX_HEALTH_RETRIES)]
    db = _make_db_with_mocked_pool(corpses)

    with pytest.raises(RuntimeError) as excinfo:
        with db._get_connection():
            pass

    assert isinstance(excinfo.value.__cause__, psycopg2.OperationalError)
    assert db.pool.putconn.call_count == MAX_HEALTH_RETRIES
    for call_obj in db.pool.putconn.call_args_list:
        assert call_obj.kwargs == {"close": True}, (
            f"every corpse must be discarded with close=True, got {call_obj}"
        )
    assert db._active_connections == 0


# ----- Mid-flight exceptions -----


def test_mid_flight_dead_conn_discarded_with_close() -> None:
    """conn dies mid-query → rollback also fails → discard with close=True."""
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([alive])

    with pytest.raises(psycopg2.OperationalError):
        with db._get_connection() as conn:
            # Simulate the socket dying after pre-ping:
            conn.rollback.side_effect = psycopg2.OperationalError("conn died")
            conn.closed = 2
            raise psycopg2.OperationalError("query failed on dead conn")

    db.pool.putconn.assert_called_once_with(alive, close=True)
    assert db._active_connections == 0


def test_serialization_failure_on_healthy_conn_recycles() -> None:
    """SerializationFailure inherits from OperationalError but the conn is fine."""
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([alive])

    with pytest.raises(psycopg2.errors.SerializationFailure):
        with db._get_connection() as conn:
            assert conn.closed == 0  # conn is alive, just an app-level conflict
            raise psycopg2.errors.SerializationFailure("conflict")

    # Recycled with close=False — pool stays warm under serializable retries.
    db.pool.putconn.assert_called_once_with(alive, close=False)
    alive.rollback.assert_called()
    assert db._active_connections == 0


def test_deadlock_detected_on_healthy_conn_recycles() -> None:
    """DeadlockDetected also inherits from OperationalError; conn stays alive."""
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([alive])

    with pytest.raises(psycopg2.errors.DeadlockDetected):
        with db._get_connection() as conn:
            assert conn.closed == 0
            raise psycopg2.errors.DeadlockDetected("deadlock")

    db.pool.putconn.assert_called_once_with(alive, close=False)
    assert db._active_connections == 0


def test_value_error_on_healthy_conn_recycles() -> None:
    """Any non-DB exception on a live conn → rollback + recycle, not destroy."""
    alive = _alive_conn()
    db = _make_db_with_mocked_pool([alive])

    with pytest.raises(ValueError):
        with db._get_connection() as conn:
            assert conn.closed == 0
            raise ValueError("app logic error")

    db.pool.putconn.assert_called_once_with(alive, close=False)
    alive.rollback.assert_called()
    assert db._active_connections == 0


def test_value_error_on_silently_dead_conn_discards() -> None:
    """ValueError raised AND the conn died silently → rollback fails → close=True."""
    alive = _alive_conn()  # passes pre-ping
    db = _make_db_with_mocked_pool([alive])

    with pytest.raises(ValueError):
        with db._get_connection() as conn:
            # Conn died between pre-ping and the user's first query.
            conn.rollback.side_effect = psycopg2.OperationalError("dead")
            conn.closed = 2
            raise ValueError("app error while conn was dying")

    # Failed rollback signals the conn is dead → close=True.
    db.pool.putconn.assert_called_once_with(alive, close=True)
    assert db._active_connections == 0


# ----- Non-dead exceptions during checkout -----


def test_pool_error_during_getconn_propagates_without_retry() -> None:
    """PoolError from getconn isn't a dead conn — propagate, don't retry."""
    db = AuthServiceDB.__new__(AuthServiceDB)
    db.pool = MagicMock()
    db.pool.getconn.side_effect = psycopg2.pool.PoolError("exhausted")
    db._active_connections = 0
    db._max_conn = 10

    with pytest.raises(psycopg2.pool.PoolError):
        with db._get_connection():
            pass

    # getconn was called once (no retry on non-DEAD), nothing to putback.
    assert db.pool.getconn.call_count == 1
    db.pool.putconn.assert_not_called()
    assert db._active_connections == 0


# ----- Counter accounting -----


def test_counter_balances_across_success_failure_and_dead() -> None:
    """active_connections must return to 0 after every path."""
    db = _make_db_with_mocked_pool([_alive_conn(), _alive_conn(), _alive_conn()])

    with db._get_connection():
        pass
    assert db._active_connections == 0

    with pytest.raises(ValueError):
        with db._get_connection():
            raise ValueError()
    assert db._active_connections == 0

    with pytest.raises(psycopg2.OperationalError):
        with db._get_connection() as conn:
            conn.rollback.side_effect = psycopg2.OperationalError("dead")
            conn.closed = 2
            raise psycopg2.OperationalError("dead")
    assert db._active_connections == 0


# ----- _is_dead_conn_error classifier -----


def test_is_dead_conn_error_interface_error_is_always_dead() -> None:
    assert AuthServiceDB._is_dead_conn_error(_alive_conn(), psycopg2.InterfaceError("x"))


def test_is_dead_conn_error_operational_on_closed_conn_is_dead() -> None:
    assert AuthServiceDB._is_dead_conn_error(_dead_conn(), psycopg2.OperationalError("x"))


def test_is_dead_conn_error_operational_on_live_conn_is_not_dead() -> None:
    """The fix for `_DEAD_CONN_ERRORS` being too broad."""
    assert not AuthServiceDB._is_dead_conn_error(
        _alive_conn(), psycopg2.OperationalError("app error")
    )


def test_is_dead_conn_error_serialization_failure_on_live_conn_is_not_dead() -> None:
    assert not AuthServiceDB._is_dead_conn_error(
        _alive_conn(), psycopg2.errors.SerializationFailure("conflict")
    )


def test_is_dead_conn_error_unrelated_exception_is_not_dead() -> None:
    assert not AuthServiceDB._is_dead_conn_error(_alive_conn(), ValueError("not a db error"))


def test_is_dead_conn_error_none_conn_assumes_dead() -> None:
    assert AuthServiceDB._is_dead_conn_error(None, psycopg2.OperationalError("getconn failed"))
