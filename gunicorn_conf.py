"""
Gunicorn configuration for API Gatekeeper.

This file is passed to gunicorn via `-c gunicorn_conf.py` so that the
prometheus_client multiprocess collector can clean up per-worker shard files
when a worker dies. Without this hook, dead-worker counter shards accumulate
in PROMETHEUS_MULTIPROC_DIR forever and inflate aggregated values.
"""
from prometheus_client import multiprocess


def child_exit(server, worker):
    multiprocess.mark_process_dead(worker.pid)
