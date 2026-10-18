"""Request-boundary correlation, privacy, timing and response-contract tests."""
import logging
import re
from threading import Lock
from typing import Any, Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask

from src import authz_tracing as tracing
from src.blueprints.authz import authz_bp
from src.database.driver import AuthServiceDB


@pytest.fixture
def traced_app(caplog: pytest.LogCaptureFixture) -> Iterator[Flask]:
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['AUTHORIZER'] = Mock()
    app.config['CORS_ALLOWED_ORIGINS'] = frozenset({'https://allowed.example'})
    app.register_blueprint(authz_bp)
    app.wsgi_app = tracing.AuthzTracingMiddleware(app.wsgi_app)
    caplog.set_level(logging.INFO)
    privacy_filter = tracing.AuthzPrivacyFilter()
    caplog.handler.addFilter(privacy_filter)
    yield app
    caplog.handler.removeFilter(privacy_filter)


def events(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.name == 'src.authz_tracing']


@pytest.mark.parametrize('status,reason', [(200, 'allowed'), (403, 'unauthorized'), (429, 'rate_limit_exceeded'), (500, 'error')])
def test_contract_and_privacy(traced_app: Flask, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, status: int, reason: str) -> None:
    requests, durations, errors = Mock(), Mock(), Mock()
    monkeypatch.setattr(tracing, "AUTH_REQUESTS_TOTAL", requests)
    monkeypatch.setattr(tracing, "AUTH_DURATION_SECONDS", durations)
    monkeypatch.setattr(tracing, "AUTH_ERRORS_TOTAL", errors)
    authorizer = traced_app.config['AUTHORIZER']
    if status == 500:
        authorizer.authorize_request.side_effect = RuntimeError('SECRET_EXCEPTION')
    else:
        authorizer.authorize_request.return_value = SimpleNamespace(
            allowed=status == 200, reason=reason, client_id='client-id',
            client_name='client-name', matched_route_id='route-id',
        )
    response = traced_app.test_client().post('/authz?SECRET_QUERY', headers={
        'X-Pguru-Trace-ID': 'a' * 32, 'X-Original-URI': '/SECRET_UID?token=SECRET_TOKEN',
        'X-Original-Method': 'GET', 'Authorization': 'Bearer SECRET_AUTH',
        'X-Original-Origin': 'https://allowed.example', 'X-Forwarded-For': '192.0.2.1',
    }, data='SECRET_BODY')
    assert response.status_code == status
    assert response.data == (b'' if status == 200 else b'Internal server error' if status == 500 else reason.encode())
    if status == 200:
        assert response.headers['X-Auth-Client-ID'] == 'client-id'
        assert response.headers['X-Auth-Route-ID'] == 'route-id'
    if status != 500:
        assert response.headers['Access-Control-Allow-Origin'] == 'https://allowed.example'
    records = events(caplog)
    assert [record.event for record in records] == ['authz_received', 'authz_completed']
    assert all(record.trace_id == 'a' * 32 and record.route == '/authz' for record in records)
    assert requests.labels.call_count == durations.labels.call_count == 1
    assert errors.labels.call_count == (1 if status == 500 else 0)
    assert records[1].status == status
    assert records[1].outcome == ('error' if status == 500 else 'allowed' if status == 200 else 'denied')
    assert records[1].elapsed_seconds >= 0
    assert isinstance(records[0].epoch_seconds, int)
    assert 'SECRET' not in str([record.__dict__ for record in caplog.records])
    assert '192.0.2.1' not in str([record.__dict__ for record in caplog.records])


@pytest.mark.parametrize('trace_id', [None, '', 'A' * 32, 'a' * 31, 'a' * 33, 'secret input'])
def test_trace_fallback_and_early_denial(traced_app: Flask, caplog: pytest.LogCaptureFixture, trace_id: str | None) -> None:
    headers = {} if trace_id is None else {'X-Pguru-Trace-ID': trace_id}
    response = traced_app.test_client().get('/authz', headers=headers)
    assert response.status_code == 400
    received, completed = events(caplog)
    assert re.fullmatch('[0-9a-f]{32}', received.trace_id)
    assert received.trace_id == completed.trace_id
    assert received.trace_source == 'generated'
    assert completed.status == 400


def test_receipt_precedes_processing_and_lower_logs_are_sanitized(traced_app: Flask, caplog: pytest.LogCaptureFixture) -> None:
    def authorize(**kwargs: Any) -> None:
        assert [record.event for record in events(caplog)] == ['authz_received']
        try:
            raise RuntimeError('SECRET_EXCEPTION')
        except RuntimeError:
            logging.getLogger('src.database.driver').exception('SECRET_MESSAGE %s', 'SECRET_ARG', extra={'client_id': 'SECRET_ID'})
        raise RuntimeError('SECRET_OUTER')
    traced_app.config['AUTHORIZER'].authorize_request.side_effect = authorize
    traced_app.test_client().get('/authz', headers={'X-Original-URI': '/private', 'X-Original-Method': 'GET'})
    diagnostic = next(record for record in caplog.records if record.name == 'src.database.driver')
    assert diagnostic.event == 'authz_diagnostic'
    assert diagnostic.exc_info is None
    assert not hasattr(diagnostic, 'client_id')
    assert 'SECRET' not in str([record.__dict__ for record in caplog.records])
    caplog.clear()
    logging.getLogger('src.database.driver').warning('Outside auth remains unchanged')
    assert caplog.records[-1].getMessage() == 'Outside auth remains unchanged'


def test_monotonic_timing_and_all_outcome_metrics(traced_app: Flask, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Mock(side_effect=[50.0, 53.25])
    monkeypatch.setattr(tracing.time, 'monotonic', clock)
    requests, durations = Mock(), Mock()
    monkeypatch.setattr(tracing, 'AUTH_REQUESTS_TOTAL', requests)
    monkeypatch.setattr(tracing, 'AUTH_DURATION_SECONDS', durations)
    traced_app.test_client().get('/authz', headers={'X-Original-URI': '/secret', 'X-Original-Method': 'SECRET_METHOD'})
    assert events(caplog)[1].elapsed_seconds == 3.25
    requests.labels.assert_called_once_with(result='denied', route_pattern='__unmatched__', method='__unknown__')
    durations.labels.return_value.observe.assert_called_once_with(3.25)


def test_logging_failure_does_not_change_response(traced_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tracing.logger, 'info', Mock(side_effect=RuntimeError('logging down')))
    response = traced_app.test_client().get('/authz')
    assert response.status_code == 400
    assert response.data == b'Missing required headers'


def test_unhandled_failure_is_rethrown_and_context_reset(caplog: pytest.LogCaptureFixture) -> None:
    def failing_app(environ: dict, start_response: Any) -> list:
        raise ValueError('private')
    caplog.set_level(logging.INFO)
    with pytest.raises(ValueError, match='private'):
        tracing.AuthzTracingMiddleware(failing_app)({'PATH_INFO': '/authz'}, Mock())
    assert events(caplog)[-1].status == 500
    assert tracing._context.get() is None


def test_non_auth_requests_are_not_traced(traced_app: Flask, caplog: pytest.LogCaptureFixture) -> None:
    assert traced_app.test_client().get('/missing').status_code == 404
    assert events(caplog) == []


def test_pool_gauge_reports_real_idle_not_unused_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.database import driver
    gauge = Mock()
    monkeypatch.setattr(driver, 'DB_CONNECTION_POOL', gauge)
    db = AuthServiceDB.__new__(AuthServiceDB)
    db.pool = SimpleNamespace(closed=True, _lock=Lock(), _used={1: object()}, _pool=[object(), object()])
    db._max_conn = 10
    db._active_connections = 1
    db._record_pool_metrics()
    assert gauge.labels.call_args_list[1].kwargs == {'state': 'idle'}
    assert gauge.labels.return_value.set.call_args_list[1].args == (2,)


def test_four_worker_aggregation_and_dead_worker_cleanup(tmp_path: Path) -> None:
    """Real separate interpreters: env must be set before prometheus import."""
    import os
    import subprocess
    import sys
    worker_code = '''
import os
from src.authz_tracing import AuthzTracingMiddleware
from src.monitoring import DB_CONNECTION_POOL

def application(environ, start_response):
    start_response('200 OK', [])
    return [b'']

def start_response(status, headers, exc_info=None):
    return None

AuthzTracingMiddleware(application)({'PATH_INFO': '/authz', 'HTTP_X_ORIGINAL_METHOD': 'GET'}, start_response)
for state, value in [('active', 1), ('idle', 2), ('max', 10)]:
    DB_CONNECTION_POOL.labels(state=state).set(value)
print(os.getpid())
'''
    env = dict(os.environ, PROMETHEUS_MULTIPROC_DIR=str(tmp_path))
    processes = [subprocess.Popen([sys.executable, '-c', worker_code], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    pids = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr
        pids.append(int(stdout.strip()))
    collector_code = '''
import sys
from prometheus_client import multiprocess
from prometheus_client.parser import text_string_to_metric_families
from src.monitoring import get_metrics

def samples():
    body, _ = get_metrics()
    return [sample for family in text_string_to_metric_families(body.decode()) for sample in family.samples]

before = samples()
for state, value in [('active', 4), ('idle', 8), ('max', 40)]:
    assert next(s.value for s in before if s.name == 'db_connection_pool_connections' and s.labels['state'] == state) == value
assert sum(s.value for s in before if s.name == 'auth_requests_total') == 4
assert sum(s.value for s in before if s.name == 'auth_duration_seconds_count') == 4
assert any(s.name == 'auth_duration_seconds_bucket' and s.labels['le'] == '3.0' for s in before)
assert all('trace_id' not in s.labels for s in before)
for pid in sys.argv[1:]:
    multiprocess.mark_process_dead(int(pid))
after = samples()
assert not any(s.name == 'db_connection_pool_connections' for s in after)
assert sum(s.value for s in after if s.name == 'auth_requests_total') == 4
'''
    result = subprocess.run([sys.executable, '-c', collector_code, *map(str, pids)], env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
