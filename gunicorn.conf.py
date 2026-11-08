"""Gunicorn configuration for the ServerPilot control plane.

WebSocket support uses simple-websocket (gthread worker). In production, use a
Redis message queue for Socket.IO and run Celery workers separately.
"""

from __future__ import annotations

import multiprocessing
import os
from pathlib import Path

bind = os.getenv("GUNICORN_BIND", "unix:/run/serverpilot/serverpilot.sock")
workers = int(
    os.getenv("GUNICORN_WORKERS", max(2, min(8, multiprocessing.cpu_count())))
)
worker_class = os.getenv("GUNICORN_WORKER_CLASS", "gthread")
threads = int(os.getenv("GUNICORN_THREADS", "8"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5
max_requests = 2000
max_requests_jitter = 200

accesslog = os.getenv("GUNICORN_ACCESS_LOG", "-")
errorlog = os.getenv("GUNICORN_ERROR_LOG", "-")
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
access_log_format = (
    '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'
)

if bind.startswith("unix:"):
    socket_path = Path(bind.removeprefix("unix:"))
    socket_path.parent.mkdir(parents=True, exist_ok=True)

forwarded_allow_ips = os.getenv("GUNICORN_FORWARDED_ALLOW_IPS", "127.0.0.1")
secure_scheme_headers = {
    "X-FORWARDED-PROTOCOL": "ssl",
    "X-FORWARDED-PROTO": "https",
    "X-FORWARDED-SSL": "on",
}
