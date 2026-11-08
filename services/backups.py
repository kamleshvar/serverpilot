"""Website backup scheduling, result handling, restoration and retention."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from flask import current_app

from ..errors import (
    ConflictError,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from ..extensions import db
from ..models import (
    AgentTask,
    AgentTaskPriority,
    Backup,
    BackupScope,
    BackupStatus,
    Severity,
    TaskStatus,
    TaskType,
    User,
    Website,
    WebsiteStatus,
)
from ..utils import as_utc, utcnow
from .agent_tasks import active_task, enqueue_task, select_agent
from .audit import notify_user, record_user_activity

logger = logging.getLogger(__name__)


def _require_access(user: User, website: Website) -> None:
    if website.owner_id != user.id and not user.is_admin:
        raise PermissionDenied("You do not have access to this website.")
    if website.status in {WebsiteStatus.DELETED, WebsiteStatus.DELETING}:
        raise ConflictError("A deleted website cannot be backed up or restored.")


def _assert_no_active_task(website: Website) -> None:
    if active_task(website):
        raise ConflictError("Wait for the current website operation to finish.")


def create_website_backup(
    user: User, website: Website, *, reason: str | None = None
) -> Backup:
    _require_access(user, website)
    _assert_no_active_task(website)
    agent = select_agent(website)
    retention = int(current_app.config.get("BACKUP_RETENTION_DAYS", 7))
    backup = Backup(
        scope=BackupScope.WEBSITE,
        website_id=website.id,
        status=BackupStatus.PENDING,
        created_by_id=user.id,
        expires_at=utcnow() + timedelta(days=retention),
        details={"reason": (reason or "manual backup")[:500]},
    )
    db.session.add(backup)
    db.session.flush()
    task = enqueue_task(
        agent=agent,
        task_type=TaskType.BACKUP,
        website=website,
        payload={"backup_id": backup.id, "website_id": website.id},
        created_by_id=user.id,
        priority=AgentTaskPriority.NORMAL,
        idempotency_key=f"backup:{backup.id}",
        max_attempts=2,
    )
    backup.details = {**(backup.details or {}), "task_id": task.id}
    db.session.commit()
    record_user_activity(
        user=user,
        action="website_backup_requested",
        resource_type="website",
        resource_id=website.id,
        description=f"Requested a backup for {website.fqdn}",
        details={"backup_id": backup.id, "task_id": task.id},
        commit=True,
    )
    logger.info("Backup %s queued for website %s", backup.id, website.id)
    return backup


def request_restore(user: User, website: Website, backup: Backup) -> AgentTask:
    _require_access(user, website)
    if backup.website_id != website.id:
        raise NotFoundError("That backup does not belong to this website.")
    if backup.scope != BackupScope.WEBSITE:
        raise ValidationError("Only website backups can be restored here.")
    if backup.status not in {BackupStatus.COMPLETED, BackupStatus.RESTORED}:
        raise ConflictError("The backup is not ready to restore.")
    expires_at = as_utc(backup.expires_at)
    if expires_at is not None and expires_at < utcnow():
        raise ConflictError("The backup has expired.")
    if not backup.storage_path:
        raise ValidationError("The backup has no stored archive path.")
    if website.status in {WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}:
        raise ConflictError("Stop the website before restoring a backup.")
    _assert_no_active_task(website)
    agent = select_agent(website)
    task = enqueue_task(
        agent=agent,
        task_type=TaskType.RESTORE,
        website=website,
        payload={
            "backup_id": backup.id,
            "website_id": website.id,
            "backup_path": backup.storage_path,
            "container_name": website.container_name,
        },
        created_by_id=user.id,
        priority=AgentTaskPriority.HIGH,
        idempotency_key=f"restore:{backup.id}:{backup.restore_count + 1}",
        max_attempts=1,
    )
    backup.status = BackupStatus.RESTORING
    backup.started_at = utcnow()
    backup.details = {**(backup.details or {}), "restore_task_id": task.id}
    db.session.commit()
    record_user_activity(
        user=user,
        action="website_restore_requested",
        resource_type="website",
        resource_id=website.id,
        description=f"Requested restore of backup {backup.id}",
        details={"backup_id": backup.id, "task_id": task.id},
        commit=True,
    )
    return task


def apply_backup_task_result(
    task: AgentTask,
    *,
    succeeded: bool,
    result: dict[str, Any] | None,
    error: str | None,
) -> Backup | None:
    payload = task.payload or {}
    backup_id = str(payload.get("backup_id") or "")
    backup = db.session.get(Backup, backup_id) if backup_id else None
    if backup is None:
        return None
    now = utcnow()
    result = result or {}
    if task.task_type == TaskType.BACKUP:
        if succeeded:
            path = str(result.get("backup_path") or "").strip()
            if not path:
                backup.status = BackupStatus.FAILED
                backup.error = "The agent did not return a backup path."
            else:
                backup.status = BackupStatus.COMPLETED
                backup.storage_path = path[:1024]
                try:
                    backup.size_bytes = int(result.get("size_bytes") or 0) or None
                except (TypeError, ValueError):
                    backup.size_bytes = None
                checksum = str(result.get("checksum_sha256") or "").strip().lower()
                backup.checksum_sha256 = checksum[:64] if checksum else None
                backup.finished_at = now
                backup.error = None
        else:
            backup.status = BackupStatus.FAILED
            backup.finished_at = now
            backup.error = (error or "The agent could not create the backup.")[:8000]
    elif task.task_type == TaskType.RESTORE:
        if succeeded:
            backup.status = BackupStatus.RESTORED
            backup.restored_at = now
            backup.finished_at = now
            backup.restore_count = int(backup.restore_count or 0) + 1
            backup.error = None
        else:
            backup.status = BackupStatus.COMPLETED
            backup.finished_at = now
            backup.error = (error or "The agent could not restore the backup.")[:8000]
        backup.details = {
            **(backup.details or {}),
            "last_restore_succeeded": bool(succeeded),
        }
    if task.website is not None:
        notify_user(
            task.website.owner,
            category=f"website_{task.task_type.value}_result",
            title=(
                f"Website {task.task_type.value} succeeded"
                if succeeded
                else f"Website {task.task_type.value} failed"
            ),
            body=(
                f"{task.task_type.value.title()} completed for {task.website.fqdn}."
                if succeeded
                else backup.error
            ),
            severity=Severity.SUCCESS if succeeded else Severity.ERROR,
            dedupe_key=f"backup-{task.task_type.value}:{task.id}",
            details={"backup_id": backup.id, "task_id": task.id},
        )
    db.session.add(backup)
    return backup


def expire_backups() -> int:
    now = utcnow()
    backups = Backup.query.filter(
        Backup.status.in_([BackupStatus.COMPLETED, BackupStatus.FAILED]),
        Backup.expires_at.isnot(None),
        Backup.expires_at < now,
    ).all()
    for backup in backups:
        backup.status = BackupStatus.EXPIRED
        db.session.add(backup)
    db.session.commit()
    return len(backups)


def list_website_backups(website: Website) -> list[Backup]:
    return (
        Backup.query.filter_by(website_id=website.id)
        .order_by(Backup.created_at.desc())
        .all()
    )


def task_backup(task: AgentTask) -> Backup | None:
    backup_id = str((task.payload or {}).get("backup_id") or "")
    if not backup_id:
        return None
    return db.session.get(Backup, backup_id)


def validate_task_state(task: AgentTask) -> None:
    if task.status not in {TaskStatus.CLAIMED, TaskStatus.RUNNING}:
        raise ConflictError("The backup task is no longer active.")
