"""
Gunicorn configuration for API Gatekeeper.

This file is passed to gunicorn via `-c gunicorn_conf.py` so that the
prometheus_client multiprocess collector can remove live-gauge shards when
a worker dies. Counter/histogram shards intentionally remain until the
container startup cleanup so worker recycling does not reset cumulative totals.
"""
from prometheus_client import multiprocess


def child_exit(server, worker):
    multiprocess.mark_process_dead(worker.pid)
