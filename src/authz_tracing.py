"""Privacy-safe /authz tracing at the WSGI application boundary."""
import logging
import os
import re
import time
from contextvars import ContextVar
from typing import Any, Callable, Iterable
from uuid import uuid4

from src.monitoring import AUTH_DURATION_SECONDS, AUTH_ERRORS_TOTAL, AUTH_REQUESTS_TOTAL

_TRACE_ID = re.compile(r'[0-9a-f]{32}\Z')
_METHODS = frozenset({'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'})
_context: ContextVar[str | None] = ContextVar('authz_trace_id', default=None)
logger = logging.getLogger(__name__)
_STANDARD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | {'message', 'asctime'}
_TRACE_FIELDS = frozenset({'event', 'trace_id', 'trace_source', 'epoch_seconds', 'route', 'worker_pid', 'status', 'outcome', 'elapsed_seconds'})


class AuthzPrivacyFilter(logging.Filter):
    """Sanitize before queueing, including exceptions from lower-level libraries.

    Outside /authz logging is unchanged. Inside it, non-tracing diagnostics keep
    only their severity and correlation ID, never messages, extras or traceback.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        trace_id = _context.get()
        if trace_id is None:
            return True
        is_trace = record.name == __name__
        for key in list(record.__dict__):
            if key not in _STANDARD_FIELDS and (not is_trace or key not in _TRACE_FIELDS):
                del record.__dict__[key]
        record.msg = 'Authz trace' if is_trace else 'Authz diagnostic'
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        record.__dict__.pop('message', None)
        record.trace_id = trace_id
        record.route = '/authz'
        if not is_trace:
            record.event = 'authz_diagnostic'
        return True


def install_privacy_filter() -> None:
    """Attach to root handlers, not root logger (propagation skips logger filters)."""
    for handler in logging.getLogger().handlers:
        if not any(isinstance(item, AuthzPrivacyFilter) for item in handler.filters):
            handler.addFilter(AuthzPrivacyFilter())


def emit(event: str, trace_source: str, **fields: Any) -> None:
    """Logging must not change an authorization response if a handler fails."""
    try:
        logger.info('Authz trace', extra={
            'event': event, 'trace_id': _context.get(), 'trace_source': trace_source,
            'epoch_seconds': int(time.time()), 'route': '/authz',
            'worker_pid': os.getpid(), **fields,
        })
    except Exception:
        pass


class AuthzTracingMiddleware:
    """Measure app entry to response-ready; excludes accept queue and transport.

    /authz responses are non-streaming. start_response marks response readiness,
    not socket flush or caller receipt. Process death can leave only a receipt.
    """
    def __init__(self, app: Callable) -> None:
        self.app = app

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        if environ.get('PATH_INFO') != '/authz':
            return self.app(environ, start_response)
        started = time.monotonic()
        supplied = environ.get('HTTP_X_PGURU_TRACE_ID', '')
        valid = isinstance(supplied, str) and _TRACE_ID.fullmatch(supplied) is not None
        trace_id = supplied if valid else uuid4().hex
        source = 'forwarded' if valid else 'generated'
        token = _context.set(trace_id)
        completed = False
        emit('authz_received', source)

        def finish(status: int) -> None:
            nonlocal completed
            if completed:
                return
            completed = True
            elapsed = max(0.0, time.monotonic() - started)
            outcome = 'error' if status >= 500 else 'allowed' if status == 200 else 'denied'
            emit('authz_completed', source, status=status, outcome=outcome, elapsed_seconds=elapsed)
            try:
                method = environ.get('HTTP_X_ORIGINAL_METHOD', '').upper()
                if method not in _METHODS:
                    method = '__unknown__'
                route = environ.get('gatekeeper.metric_route', '__unmatched__')
                AUTH_REQUESTS_TOTAL.labels(result=outcome, route_pattern=route, method=method).inc()
                AUTH_DURATION_SECONDS.labels(route_pattern=route, method=method).observe(elapsed)
                if outcome == 'error':
                    AUTH_ERRORS_TOTAL.labels(error_type='server_error').inc()
            except Exception:
                pass

        def response_ready(status: str, headers: list, exc_info: Any = None) -> Callable:
            write = start_response(status, headers, exc_info)
            finish(int(status.split(' ', 1)[0]))
            return write

        try:
            return self.app(environ, response_ready)
        except BaseException:
            finish(500)
            raise
        finally:
            _context.reset(token)
