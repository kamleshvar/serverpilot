"""Signed agent task queue selection and dispatch."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from flask import current_app

from ..errors import AgentUnavailable
from ..extensions import db
from ..models import (
    AgentCredential,
    AgentStatus,
    AgentTask,
    AgentTaskPriority,
    DeploymentStatus,
    Server,
    ServerAgent,
    ServerApprovalStatus,
    ServerStatus,
    TaskStatus,
    TaskType,
    Website,
)
from ..models.base import new_uuid
from ..utils import utcnow
from .agent_auth import sign_for_agent
from .encryption import get_encryption

logger = logging.getLogger(__name__)

ACTIVE_TASK_STATUSES = {TaskStatus.PENDING, TaskStatus.CLAIMED, TaskStatus.RUNNING}
ACTIVE_DEPLOYMENT_STATUSES = {
    DeploymentStatus.QUEUED,
    DeploymentStatus.BUILDING,
    DeploymentStatus.DEPLOYING,
    DeploymentStatus.HEALTH_CHECK,
}


def agent_secret(agent: ServerAgent) -> str:
    credential = (
        AgentCredential.query.filter_by(agent_id=agent.id)
        .filter(AgentCredential.revoked_at.is_(None))
        .order_by(AgentCredential.created_at.desc())
        .first()
    )
    if credential is None or not credential.is_valid:
        raise AgentUnavailable("The deployment agent has no valid credential.")
    secret = get_encryption().decrypt(credential.secret_encrypted)
    if not secret:
        raise AgentUnavailable("The deployment agent credential cannot be read.")
    return secret


def select_agent(website: Website | None = None) -> ServerAgent:
    cutoff = utcnow() - timedelta(
        seconds=int(current_app.config.get("AGENT_OFFLINE_AFTER_SECONDS", 120))
    )
    query = (
        ServerAgent.query.join(Server)
        .filter(
            ServerAgent.status == AgentStatus.ACTIVE,
            ServerAgent.last_seen_at >= cutoff,
            Server.status == ServerStatus.ONLINE,
            Server.approval_status == ServerApprovalStatus.APPROVED,
            Server.deleted_at.is_(None),
            Server.last_heartbeat_at >= cutoff,
        )
        .order_by(Server.is_default.desc(), ServerAgent.last_seen_at.desc())
    )
    if website is not None and website.server_id:
        query = query.filter(ServerAgent.server_id == website.server_id)
    agent = query.first()
    if agent is None:
        raise AgentUnavailable(
            "No healthy deployment agent is connected. Ask the platform operator "
            "to complete the agent installation."
        )
    return agent


def active_task(
    website: Website, task_types: set[TaskType] | None = None
) -> AgentTask | None:
    query = AgentTask.query.filter(
        AgentTask.website_id == website.id,
        AgentTask.status.in_(list(ACTIVE_TASK_STATUSES)),
    )
    if task_types:
        query = query.filter(AgentTask.task_type.in_(list(task_types)))
    return query.order_by(AgentTask.created_at.desc()).first()


def enqueue_task(
    *,
    agent: ServerAgent,
    task_type: TaskType,
    website: Website | None,
    deployment=None,
    payload: dict[str, Any],
    created_by_id: str | None,
    priority: AgentTaskPriority = AgentTaskPriority.NORMAL,
    idempotency_key: str | None = None,
    max_attempts: int = 3,
) -> AgentTask:
    secret = agent_secret(agent)
    if idempotency_key:
        existing = AgentTask.query.filter_by(
            idempotency_key=idempotency_key
        ).one_or_none()
        if existing is not None:
            return existing
    task = AgentTask(
        agent_id=agent.id,
        website_id=website.id if website else None,
        deployment_id=deployment.id if deployment else None,
        task_type=task_type,
        status=TaskStatus.PENDING,
        priority=priority,
        payload=payload,
        signature=sign_for_agent(secret, payload),
        idempotency_key=idempotency_key or new_uuid(),
        max_attempts=max_attempts,
        expires_at=utcnow()
        + timedelta(seconds=int(current_app.config.get("AGENT_TASK_TIMEOUT", 300))),
        created_by_id=created_by_id,
    )
    db.session.add(task)
    db.session.flush()
    if website is not None and website.server_id is None:
        website.server_id = agent.server_id
    return task


def claim_next_task(agent: ServerAgent) -> AgentTask | None:
    now = utcnow()
    AgentTask.query.filter(
        AgentTask.agent_id == agent.id,
        AgentTask.status == TaskStatus.PENDING,
        AgentTask.expires_at < now,
    ).update(
        {"status": TaskStatus.EXPIRED, "completed_at": now}, synchronize_session=False
    )
    in_flight = (
        AgentTask.query.filter(
            AgentTask.agent_id == agent.id,
            AgentTask.status.in_([TaskStatus.CLAIMED, TaskStatus.RUNNING]),
            AgentTask.expires_at >= now,
        )
        .order_by(AgentTask.created_at.asc())
        .first()
    )
    if in_flight is not None:
        db.session.commit()
        return in_flight
    task = (
        AgentTask.query.filter(
            AgentTask.agent_id == agent.id,
            AgentTask.status == TaskStatus.PENDING,
            AgentTask.expires_at >= now,
        )
        .order_by(AgentTask.created_at.asc())
        .with_for_update()
        .first()
    )
    if task is None:
        db.session.commit()
        return None
    task.status = TaskStatus.CLAIMED
    task.attempts += 1
    task.claimed_at = now
    task.started_at = task.started_at or now
    db.session.commit()
    return task


def task_payload_for_agent(task: AgentTask) -> dict[str, Any]:
    """Build the signed wire payload without persisting decrypted credentials."""
    payload = dict(task.payload or {})
    encrypted_token = payload.pop("installation_token_encrypted", None)
    if encrypted_token:
        payload["installation_token"] = get_encryption().decrypt(encrypted_token)
    signature = sign_for_agent(agent_secret(task.agent), payload)
    return {
        "id": task.id,
        "type": task.task_type.value,
        "payload": payload,
        "signature": signature,
        "expires_at": task.expires_at.isoformat(),
        "attempt": task.attempts,
    }


def expire_stale_tasks() -> int:
    now = utcnow()
    tasks = AgentTask.query.filter(
        AgentTask.status.in_(
            [TaskStatus.PENDING, TaskStatus.CLAIMED, TaskStatus.RUNNING]
        ),
        AgentTask.expires_at < now,
    ).all()
    for task in tasks:
        task.status = TaskStatus.EXPIRED
        task.completed_at = now
        if task.website is not None:
            task.website.status_detail = (
                "The deployment agent did not complete the task in time. Retry or "
                "contact the platform operator."
            )
        if task.task_type == TaskType.DEPLOY and task.deployment is not None:
            task.deployment.status = DeploymentStatus.FAILED
            task.deployment.failure_reason = (
                "The deployment agent did not complete the task before it expired."
            )
            task.deployment.finished_at = now
            if (
                task.website is not None
                and task.website.forced_stop_at is None
                and task.website.status.value == "building"
            ):
                from ..models import WebsiteStatus

                task.website.status = WebsiteStatus.FAILED
                task.website.status_changed_at = now
        elif task.task_type in {TaskType.BACKUP, TaskType.RESTORE}:
            from .backups import apply_backup_task_result

            apply_backup_task_result(
                task,
                succeeded=False,
                result={},
                error="The agent task expired before it completed.",
            )
    if tasks:
        db.session.commit()
    return len(tasks)
