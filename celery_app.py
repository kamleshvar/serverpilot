"""Celery application and periodic maintenance schedule."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from . import create_app

flask_app = create_app()
celery = Celery(
    "serverpilot",
    broker=flask_app.config["CELERY_BROKER_URL"],
    backend=flask_app.config["CELERY_RESULT_BACKEND"],
    include=["serverpilot.background_tasks"],
)
celery.conf.update(
    task_always_eager=bool(flask_app.config.get("CELERY_TASK_ALWAYS_EAGER", False)),
    task_eager_propagates=bool(
        flask_app.config.get("CELERY_TASK_EAGER_PROPAGATES", True)
    ),
    task_time_limit=int(flask_app.config.get("CELERY_TASK_TIME_LIMIT", 900)),
    task_ignore_result=True,
    timezone="UTC",
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "refresh-server-health": {
            "task": "serverpilot.refresh_server_health",
            "schedule": 60.0,
        },
        "expire-stale-agent-tasks": {
            "task": "serverpilot.expire_stale_agent_tasks",
            "schedule": 60.0,
        },
        "expire-backups": {
            "task": "serverpilot.expire_backups",
            "schedule": crontab(hour=3, minute=15),
        },
        "check-dns-records": {
            "task": "serverpilot.check_dns_records",
            "schedule": crontab(minute="*/30"),
        },
        "purge-expired-sessions": {
            "task": "serverpilot.purge_expired_sessions",
            "schedule": crontab(hour=4, minute=10),
        },
    },
)
