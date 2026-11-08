"""Celery tasks for scheduled maintenance and integration synchronization."""

from __future__ import annotations

import logging

from .celery_app import celery, flask_app
from .extensions import db
from .models import AgentNonce, UserSession
from .services.agent_tasks import expire_stale_tasks
from .services.backups import expire_backups
from .services.cloudflare import check_website_dns, cloudflare_configured
from .services.server_monitoring import refresh_server_health
from .utils import utcnow

logger = logging.getLogger(__name__)


def _with_app_context():
    return flask_app.app_context()


@celery.task(name="serverpilot.refresh_server_health")
def refresh_server_health_task() -> int:
    with _with_app_context():
        return refresh_server_health()


@celery.task(name="serverpilot.expire_stale_agent_tasks")
def expire_stale_agent_tasks_task() -> int:
    with _with_app_context():
        return expire_stale_tasks()


@celery.task(name="serverpilot.expire_backups")
def expire_backups_task() -> int:
    with _with_app_context():
        return expire_backups()


@celery.task(name="serverpilot.check_dns_records")
def check_dns_records_task() -> int:
    with _with_app_context():
        if not cloudflare_configured():
            return 0
        from .models import Website, WebsiteStatus

        websites = Website.query.filter(
            Website.status != WebsiteStatus.DELETED,
            Website.deleted_at.is_(None),
        ).all()
        checked = 0
        for website in websites:
            try:
                check_website_dns(website, commit=True)
                checked += 1
            except Exception:
                db.session.rollback()
                logger.exception("DNS check failed for website %s", website.id)
        return checked


@celery.task(name="serverpilot.purge_expired_sessions")
def purge_expired_sessions_task() -> dict[str, int]:
    with _with_app_context():
        now = utcnow()
        sessions = UserSession.query.filter(
            (UserSession.expires_at < now) | (UserSession.revoked_at.isnot(None))
        ).delete(synchronize_session=False)
        nonces = AgentNonce.query.filter(AgentNonce.expires_at < now).delete(
            synchronize_session=False
        )
        db.session.commit()
        return {"sessions": sessions, "nonces": nonces}
