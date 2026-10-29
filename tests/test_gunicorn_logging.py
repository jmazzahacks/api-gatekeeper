"""Master logging routing and lifecycle regressions, with no external services."""
import logging
import runpy
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from byteforge_loki_logging import flush_logging
from gunicorn.config import Config

from src.gunicorn_logging import GatekeeperLogger


@pytest.fixture
def isolated_logging(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Restore process-global loggers after exercising real configuration."""
    names = ('', 'gunicorn', 'gunicorn.error', 'gunicorn.access')
    saved = []
    for name in names:
        logger = logging.getLogger(name)
        saved.append((logger, logger.handlers[:], logger.level, logger.propagate))
    monkeypatch.setenv('PYTHON_DOTENV_DISABLED', '1')
    monkeypatch.setenv('DEBUG_LOCAL', 'true')
    monkeypatch.setenv('LOG_LEVEL', 'INFO')
    try:
        yield
    finally:
        flush_logging()
        for logger, handlers, level, propagate in saved:
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate


def test_master_records_reach_loki_once_on_setup_and_reload(
    monkeypatch: pytest.MonkeyPatch, isolated_logging: None,
) -> None:
    monkeypatch.setenv('DEBUG_LOCAL', 'false')
    monkeypatch.setenv('LOKI_ENDPOINT', 'http://127.0.0.1:1/loki/api/v1/push')
    monkeypatch.setenv('LOKI_USER', 'test')
    monkeypatch.setenv('LOKI_PASSWORD', 'test')
    monkeypatch.setenv('LOKI_CA_BUNDLE_PATH', 'false')
    monkeypatch.setattr('byteforge_loki_logging.logging_config._test_loki_connection', Mock(return_value=(True, '')))
    posted = Mock()
    monkeypatch.setattr('byteforge_loki_logging.logging_config.SafeLokiEmitter._post_to_loki', posted)
    cfg = Config()
    gunicorn_logger = GatekeeperLogger(cfg)
    gunicorn_logger.info('Starting master regression')
    gunicorn_logger.critical('WORKER TIMEOUT (pid:123)')
    assert flush_logging()
    gunicorn_logger.setup(cfg)
    gunicorn_logger.info('Handling signal: term')
    assert flush_logging()
    payloads = str(posted.call_args_list)
    for message in ('Starting master regression', 'WORKER TIMEOUT (pid:123)', 'Handling signal: term'):
        assert payloads.count(message) == 1
    assert 'api-gatekeeper' in payloads
    assert 'gunicorn.error' in payloads
    assert 'CRITICAL' in payloads


def test_local_mode_and_level(monkeypatch: pytest.MonkeyPatch, isolated_logging: None, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv('LOG_LEVEL', 'WARNING')
    gunicorn_logger = GatekeeperLogger(Config())
    gunicorn_logger.info('hidden-info')
    gunicorn_logger.warning('visible-warning')
    output = capsys.readouterr().out
    assert 'visible-warning' in output
    assert 'hidden-info' not in output


def test_exit_hooks_preserve_metrics_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    flush = Mock()
    cleanup = Mock()
    monkeypatch.setattr('byteforge_loki_logging.flush_logging', flush)
    monkeypatch.setattr('prometheus_client.multiprocess.mark_process_dead', cleanup)
    config = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'gunicorn_conf.py'))
    assert config['logger_class'] is GatekeeperLogger
    worker = SimpleNamespace(pid=123)
    config['child_exit'](None, worker)
    cleanup.assert_called_once_with(123)
    config['worker_exit'](None, worker)
    config['on_exit'](None)
    assert flush.call_count == 2
    flush.assert_called_with(timeout=5.0)


def test_loki_outage_keeps_master_logs_on_stdout(
    monkeypatch: pytest.MonkeyPatch, isolated_logging: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv('DEBUG_LOCAL', 'false')
    for name in ('LOKI_ENDPOINT', 'LOKI_USER', 'LOKI_PASSWORD', 'LOKI_CA_BUNDLE_PATH'):
        monkeypatch.setenv(name, 'test')
    monkeypatch.setattr(
        'byteforge_loki_logging.logging_config._test_loki_connection',
        Mock(return_value=(False, 'simulated outage')),
    )
    gunicorn_logger = GatekeeperLogger(Config())
    gunicorn_logger.error('master fallback record')
    output = capsys.readouterr()
    assert output.out.count('master fallback record') == 1
    assert 'Falling back to stdout' in output.err


def test_replaced_gunicorn_file_handler_is_closed(
    monkeypatch: pytest.MonkeyPatch, isolated_logging: None, tmp_path: Path,
) -> None:
    original = logging.FileHandler
    opened: list[logging.FileHandler] = []

    def track_handler(filename: str) -> logging.FileHandler:
        handler = original(filename)
        opened.append(handler)
        return handler

    monkeypatch.setattr('gunicorn.glogging.logging.FileHandler', track_handler)
    cfg = Config()
    cfg.set('errorlog', str(tmp_path / 'gunicorn.log'))
    gunicorn_logger = GatekeeperLogger(cfg)
    gunicorn_logger.setup(cfg)
    assert len(opened) == 2
    assert all(handler.stream is None for handler in opened)
