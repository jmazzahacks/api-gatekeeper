"""Gunicorn logging lifecycle and Prometheus worker cleanup."""
from byteforge_loki_logging import flush_logging
from gunicorn.arbiter import Arbiter
from gunicorn.workers.base import Worker
from prometheus_client import multiprocess

from src.gunicorn_logging import GatekeeperLogger

logger_class = GatekeeperLogger


def child_exit(server: Arbiter, worker: Worker) -> None:
    """Remove live-gauge shards; retain cumulative counters and histograms."""
    multiprocess.mark_process_dead(worker.pid)


def worker_exit(server: Arbiter, worker: Worker) -> None:
    """Drain worker exit records before the process terminates."""
    flush_logging(timeout=5.0)


def on_exit(server: Arbiter) -> None:
    """Drain the arbiter's final shutdown records."""
    flush_logging(timeout=5.0)
