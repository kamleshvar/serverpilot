"""Deployment orchestration and agent task result handling."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..errors import (
    AgentUnavailable,
    ConflictError,
    PermissionDenied,
    ValidationError,
)
from ..extensions import db
from ..models import (
    AdminActionResult,
    AgentTask,
    AgentTaskPriority,
    Container,
    ContainerStatus,
    Deployment,
    DeploymentLog,
    DeploymentStatus,
    DeploymentTrigger,
    GithubInstallationStatus,
    InitiatorType,
    LogLevel,
    LogSource,
    StopReason,
    TaskStatus,
    TaskType,
    User,
    Website,
    WebsiteStatus,
)
from ..utils import as_utc, utcnow
from .agent_tasks import (
    ACTIVE_DEPLOYMENT_STATUSES,
    active_task,
    enqueue_task,
    select_agent,
)
from .audit import notify_admins, record_admin_action, record_user_activity
from .encryption import get_encryption
from .github_app import installation_token_for_commit
from .quota import assert_website_ram_available
from .websites import assert_website_can_start

logger = logging.getLogger(__name__)


def _active_deployment(website: Website) -> Deployment | None:
    return (
        Deployment.query.filter(
            Deployment.website_id == website.id,
            Deployment.status.in_(list(ACTIVE_DEPLOYMENT_STATUSES)),
        )
        .order_by(Deployment.created_at.desc())
        .first()
    )


def _next_deployment_number(website: Website) -> int:
    current = (
        db.session.query(func.max(Deployment.number))
        .filter(Deployment.website_id == website.id)
        .scalar()
    )
    return int(current or 0) + 1


def _require_installation(website: Website):
    installation = website.github_installation
    if installation is None:
        return None
    if installation.status != GithubInstallationStatus.ACTIVE:
        raise ValidationError("The GitHub App installation is not active.")
    return installation


def _resolve_source_access(
    user: User, website: Website, installation
) -> tuple[str, dict[str, Any]]:
    """Return (clone token, commit metadata) for the website's repository.

    Prefers the GitHub App installation token; otherwise falls back to the
    owner's linked GitHub OAuth authorization, which also allows repository
    archives to be downloaded by the deployment agent.
    """
    repository = website.repository_full_name or ""
    branch = website.branch or "main"
    if installation is not None:
        return installation_token_for_commit(
            installation.installation_id, repository, branch
        )
    from .github_app import oauth_commit_for_ref

    return oauth_commit_for_ref(website.owner, repository, branch)


def create_deployment(
    user: User,
    website: Website,
    *,
    trigger: DeploymentTrigger = DeploymentTrigger.MANUAL,
    initiator_type: InitiatorType = InitiatorType.USER,
    admin: User | None = None,
) -> Deployment:
    """Queue a real build/deploy task for the assigned agent."""
    if website.owner_id != user.id and not user.is_admin:
        raise PermissionDenied("You do not have access to this website.")
    if website.status == WebsiteStatus.DELETED:
        raise ConflictError("This website has been deleted.")
    if website.forced_stop_at is not None or website.is_admin_stopped:
        raise PermissionDenied("This website is locked by an administrator.")
    if website.maintenance_enabled:
        raise ConflictError("This website is in platform maintenance mode.")
    if _active_deployment(website) is not None:
        raise ConflictError("A deployment is already in progress for this website.")
    if active_task(website, {TaskType.DEPLOY, TaskType.START, TaskType.STOP}):
        raise ConflictError("A website operation is already queued for the agent.")
    installation = _require_installation(website)
    assert_website_ram_available(user, website)

    token, commit = _resolve_source_access(user, website, installation)
    agent = select_agent(website)

    number = _next_deployment_number(website)
    image_tag = f"serverpilot/{website.id}:{number}"
    deployment = Deployment(
        website_id=website.id,
        user_id=website.owner_id,
        initiated_by_id=user.id,
        initiator_type=initiator_type,
        trigger=trigger,
        number=number,
        status=DeploymentStatus.QUEUED,
        repository_full_name=website.repository_full_name,
        branch=website.branch,
        commit_sha=commit["sha"],
        commit_message=commit["message"],
        commit_author=commit["author"],
        source_ref=website.branch,
        image_tag=image_tag,
        config_snapshot={
            "framework": website.framework.value,
            "root_directory": website.root_directory,
            "build_command": website.build_command,
            "start_command": website.start_command,
            "internal_port": website.internal_port,
            "healthcheck_path": website.healthcheck_path,
            "ram_limit_mb": website.ram_limit_mb,
            "storage_limit_mb": website.storage_limit_mb,
            "cpu_limit": website.cpu_limit,
        },
    )
    db.session.add(deployment)
    try:
        db.session.flush()
    except IntegrityError as exc:
        db.session.rollback()
        raise ConflictError(
            "A deployment was queued concurrently. Refresh and retry."
        ) from exc

    payload = {
        "deployment_id": deployment.id,
        "deployment_number": number,
        "website_id": website.id,
        "fqdn": website.fqdn,
        "container_name": website.container_name,
        "repository_full_name": website.repository_full_name,
        "branch": website.branch,
        "commit_sha": deployment.commit_sha,
        "installation_token_encrypted": get_encryption().encrypt(token),
        "framework": website.framework.value,
        "root_directory": website.root_directory,
        "build_command": website.build_command,
        "start_command": website.start_command,
        "dockerfile_path": website.dockerfile_path,
        "internal_port": website.internal_port,
        "healthcheck_path": website.healthcheck_path,
        "healthcheck_timeout_seconds": website.healthcheck_timeout_seconds,
        "ram_limit_mb": website.ram_limit_mb,
        "storage_limit_mb": website.storage_limit_mb,
        "cpu_limit": website.cpu_limit,
        "image_tag": image_tag,
    }
    enqueue_task(
        agent=agent,
        task_type=TaskType.DEPLOY,
        website=website,
        deployment=deployment,
        payload=payload,
        created_by_id=user.id,
        priority=AgentTaskPriority.HIGH,
        idempotency_key=f"deploy:{deployment.id}",
        max_attempts=1,
    )
    website.status = WebsiteStatus.BUILDING
    website.status_detail = f"Deployment #{number} is queued for the agent."
    website.status_changed_at = utcnow()
    website.image_tag = image_tag
    db.session.commit()
    record_user_activity(
        user=user,
        action="deployment_queued",
        resource_type="deployment",
        resource_id=deployment.id,
        description=f"Queued deployment #{number} for {website.fqdn}",
        details={"commit_sha": deployment.commit_sha, "trigger": trigger.value},
    )
    record_admin_action(
        admin=admin,
        action="deployment_queued",
        resource_type="deployment",
        resource_id=deployment.id,
        details={"website_id": website.id, "number": number},
    )
    db.session.commit()
    logger.info("Deployment %s#%s queued for %s", website.id, number, agent.name)
    return deployment


def request_start(user: User, website: Website) -> AgentTask:
    if website.status in {WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}:
        raise ConflictError("This website is already running or building.")
    assert_website_can_start(user, website)
    if active_task(website):
        raise ConflictError("A website operation is already queued for the agent.")
    if website.current_deployment_id and website.container_name:
        agent = select_agent(website)
        task = enqueue_task(
            agent=agent,
            task_type=TaskType.START,
            website=website,
            payload={
                "website_id": website.id,
                "container_name": website.container_name,
                "fqdn": website.fqdn,
                "internal_port": website.internal_port,
                "framework": website.framework.value,
                "healthcheck_path": website.healthcheck_path,
                "healthcheck_timeout_seconds": website.healthcheck_timeout_seconds,
            },
            created_by_id=user.id,
            priority=AgentTaskPriority.HIGH,
            idempotency_key=f"start:{website.id}:{int(utcnow().timestamp())}",
        )
        website.status_detail = "Start requested; waiting for the agent."
        website.status_changed_at = utcnow()
        db.session.commit()
        record_user_activity(
            user=user,
            action="website_start_requested",
            resource_type="website",
            resource_id=website.id,
            description=f"Requested start for {website.fqdn}",
            commit=True,
        )
        return task
    deployment = create_deployment(user, website, trigger=DeploymentTrigger.MANUAL)
    task = AgentTask.query.filter_by(deployment_id=deployment.id).one()
    return task


def request_stop(
    user: User,
    website: Website,
    *,
    admin: User | None = None,
    reason: StopReason = StopReason.USER_REQUESTED,
    force: bool = False,
) -> AgentTask | None:
    if website.status not in {WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}:
        raise ConflictError("This website is not running.")
    if active_task(website, {TaskType.STOP}):
        raise ConflictError("A stop operation is already queued for the agent.")
    try:
        agent = select_agent(website)
    except AgentUnavailable:
        if not force:
            raise
        website.status = WebsiteStatus.ADMIN_FORCED_STOP
        website.status_detail = "Administrator stop recorded; agent is offline."
        website.status_changed_at = utcnow()
        db.session.commit()
        return None
    task = enqueue_task(
        agent=agent,
        task_type=TaskType.STOP,
        website=website,
        payload={
            "website_id": website.id,
            "container_name": website.container_name,
            "fqdn": website.fqdn,
            "force": force,
            "reason": reason.value,
        },
        created_by_id=user.id,
        priority=AgentTaskPriority.HIGH,
        idempotency_key=f"stop:{website.id}:{int(utcnow().timestamp())}",
    )
    website.status_detail = (
        "Administrator stop requested; waiting for the agent."
        if force
        else "Stop requested; waiting for the agent."
    )
    website.status_changed_at = utcnow()
    db.session.commit()
    record_user_activity(
        user=user,
        action="website_stop_requested",
        resource_type="website",
        resource_id=website.id,
        description=f"Requested stop for {website.fqdn}",
        details={"reason": reason.value, "force": force},
    )
    record_admin_action(
        admin=admin,
        action="website_force_stop_requested" if force else "website_stop_requested",
        resource_type="website",
        resource_id=website.id,
        details={"reason": reason.value},
    )
    db.session.commit()
    return task


def force_stop_website(admin: User, website: Website, reason: str) -> AgentTask | None:
    if not admin.is_admin:
        raise PermissionDenied("Administrator access is required.")
    cleaned = (reason or "").strip()
    if not cleaned:
        raise ValidationError("A reason is required to force-stop a website.")
    task = None
    if website.status in {WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}:
        try:
            task = request_stop(
                admin,
                website,
                admin=admin,
                reason=StopReason.ADMIN_FORCED_STOP,
                force=True,
            )
        except (ConflictError, AgentUnavailable):
            task = None
    now = utcnow()
    website.forced_stop_by_id = admin.id
    website.forced_stop_at = now
    website.forced_stop_reason = cleaned[:4000]
    website.stop_reason = StopReason.ADMIN_FORCED_STOP
    website.status = WebsiteStatus.ADMIN_FORCED_STOP
    website.status_detail = (
        "Stopped by an administrator; waiting for the agent to stop the container."
        if task is not None
        else "Stopped by an administrator. User restarts are blocked."
    )
    website.status_changed_at = now
    db.session.add(website)
    db.session.commit()
    record_admin_action(
        admin=admin,
        action="website_force_stopped",
        resource_type="website",
        resource_id=website.id,
        details={"reason": cleaned, "task_id": task.id if task else None},
        commit=True,
    )
    return task


def append_logs(deployment: Deployment, entries: list[dict[str, Any]]) -> int:
    if not entries:
        return 0
    current = (
        db.session.query(func.max(DeploymentLog.sequence))
        .filter(DeploymentLog.deployment_id == deployment.id)
        .scalar()
        or 0
    )
    created = 0
    for entry in entries[:500]:
        message = str(entry.get("message") or "").strip()
        if not message:
            continue
        current += 1
        try:
            source = LogSource(str(entry.get("source") or "deployment"))
        except ValueError:
            source = LogSource.DEPLOYMENT
        try:
            level = LogLevel(str(entry.get("level") or "info"))
        except ValueError:
            level = LogLevel.INFO
        db.session.add(
            DeploymentLog(
                deployment_id=deployment.id,
                sequence=current,
                source=source,
                level=level,
                message=message[:20000],
            )
        )
        created += 1
    return created


def _container_for(website: Website) -> Container | None:
    return Container.query.filter_by(website_id=website.id).one_or_none()


def _mark_container_running(
    website: Website, result: dict[str, Any], deployment: Deployment
) -> None:
    container = _container_for(website)
    if container is None:
        container = Container(
            website_id=website.id,
            name=website.container_name or f"sp-{website.id.replace('-', '')[:24]}",
            server_id=website.server_id,
            status=ContainerStatus.RUNNING,
        )
        db.session.add(container)
    container.server_id = website.server_id
    container.docker_container_id = (
        str(result.get("container_id") or container.docker_container_id or "")[:128]
        or None
    )
    container.image = deployment.image_tag
    container.status = ContainerStatus.RUNNING
    container.health_status = "healthy"
    container.internal_port = website.internal_port
    container.cpu_limit = website.cpu_limit
    container.ram_limit_mb = website.ram_limit_mb
    container.storage_limit_mb = website.storage_limit_mb
    container.started_at = container.started_at or utcnow()
    container.stopped_at = None
    container.last_seen_at = utcnow()


def _mark_container_stopped(website: Website) -> None:
    container = _container_for(website)
    if container is not None:
        container.status = ContainerStatus.STOPPED
        container.health_status = None
        container.stopped_at = utcnow()
        container.last_seen_at = utcnow()


def _mark_container_removed(website: Website) -> None:
    container = _container_for(website)
    if container is not None:
        container.status = ContainerStatus.REMOVED
        container.health_status = None
        container.stopped_at = container.stopped_at or utcnow()
        container.last_seen_at = utcnow()


def apply_task_result(
    task: AgentTask,
    *,
    succeeded: bool,
    result: dict[str, Any] | None,
    error: str | None,
) -> bool:
    if task.status not in {TaskStatus.CLAIMED, TaskStatus.RUNNING}:
        return False
    now = utcnow()
    result = result or {}
    task.completed_at = now
    task.result = result
    task.error = (error or "")[:8000] or None
    task.status = TaskStatus.SUCCEEDED if succeeded else TaskStatus.FAILED
    website = task.website
    deployment = task.deployment

    if task.task_type == TaskType.DEPLOY and deployment is not None:
        deployment.finished_at = now
        deployment.started_at = deployment.started_at or task.claimed_at
        started_at = as_utc(deployment.started_at)
        if started_at:
            deployment.duration_seconds = max(0.0, (now - started_at).total_seconds())
        if succeeded:
            Deployment.query.filter(
                Deployment.website_id == deployment.website_id,
                Deployment.id != deployment.id,
                Deployment.is_current.is_(True),
            ).update({"is_current": False}, synchronize_session=False)
            deployment.status = DeploymentStatus.SUCCEEDED
            deployment.is_current = True
            deployment.failure_reason = None
            website.current_deployment_id = deployment.id
            website.last_deployed_at = now
            website.image_tag = deployment.image_tag
            if website.forced_stop_at is not None:
                website.status = WebsiteStatus.ADMIN_FORCED_STOP
                website.status_detail = (
                    "Deployment finished, but this website remains locked by an "
                    "administrator."
                )
            else:
                website.status = WebsiteStatus.RUNNING
                website.status_detail = f"Deployment #{deployment.number} is live."
                website.stop_reason = None
                website.stop_detail = None
            website.status_changed_at = now
            if website.server_id:
                website.server_id = task.agent.server_id
            _mark_container_running(website, result, deployment)
            append_logs(
                deployment,
                [
                    {
                        "message": "Deployment succeeded and passed its health check.",
                        "level": "info",
                    }
                ],
            )
        else:
            deployment.status = DeploymentStatus.FAILED
            deployment.failure_reason = (
                error or "The agent reported a failed deployment."
            )[:8000]
            if website.forced_stop_at is None:
                website.status = WebsiteStatus.FAILED
                website.status_detail = "Deployment failed. Review the deployment logs."
                website.status_changed_at = now
            append_logs(
                deployment,
                [
                    {
                        "message": deployment.failure_reason,
                        "level": "error",
                        "source": "system",
                    }
                ],
            )
    elif task.task_type == TaskType.START and website is not None:
        if succeeded:
            website.status = WebsiteStatus.RUNNING
            website.status_detail = "Website started by the agent."
            website.status_changed_at = now
            container = _container_for(website)
            if container is not None:
                container.status = ContainerStatus.RUNNING
                container.started_at = container.started_at or now
                container.stopped_at = None
        elif website.forced_stop_at is None:
            website.status = WebsiteStatus.FAILED
            website.status_detail = "The agent could not start the website."
            website.status_changed_at = now
    elif task.task_type == TaskType.STOP and website is not None:
        if succeeded:
            _mark_container_stopped(website)
            if website.forced_stop_at is not None:
                website.status = WebsiteStatus.ADMIN_FORCED_STOP
                website.stop_reason = StopReason.ADMIN_FORCED_STOP
                website.status_detail = (
                    "Stopped by an administrator. User restarts are blocked."
                )
            else:
                website.status = WebsiteStatus.USER_STOPPED
                website.stop_reason = StopReason.USER_REQUESTED
                website.status_detail = "Website stopped."
            website.status_changed_at = now
        else:
            website.status = WebsiteStatus.RUNNING
            website.status_detail = "The agent could not stop the website."
            website.status_changed_at = now
    elif task.task_type == TaskType.RESTART and website is not None:
        website.status = WebsiteStatus.RUNNING if succeeded else WebsiteStatus.FAILED
        website.status_detail = (
            "Website restarted by the agent." if succeeded else "Restart failed."
        )
        website.status_changed_at = now
    elif task.task_type in {TaskType.BACKUP, TaskType.RESTORE}:
        from .backups import apply_backup_task_result

        apply_backup_task_result(task, succeeded=succeeded, result=result, error=error)
    elif task.task_type in {TaskType.DELETE, TaskType.REMOVE}:
        if succeeded:
            if website is not None:
                _mark_container_removed(website)
                website.status = WebsiteStatus.DELETED
                website.deleted_at = website.deleted_at or now
                website.container_name = None
                website.status_detail = "Website resources removed by the agent."
                website.status_changed_at = now
        else:
            notify_admins(
                category="website_cleanup_failed",
                title="Website cleanup failed",
                body=(
                    "The agent could not remove all remote resources for a deleted "
                    "website. Manual cleanup may be required."
                ),
                dedupe_key=f"website-cleanup-failed:{task.id}",
                details={
                    "task_id": task.id,
                    "website_id": task.website_id,
                    "error": task.error,
                },
            )

    db.session.commit()
    if website is not None:
        if succeeded:
            record_user_activity(
                user=website.owner,
                action=f"{task.task_type.value}_succeeded",
                resource_type="website",
                resource_id=website.id,
                description=f"Agent completed {task.task_type.value} for {website.fqdn}",
                details={"task_id": task.id, "deployment_id": task.deployment_id},
            )
            record_admin_action(
                admin=None,
                action=f"agent_{task.task_type.value}_succeeded",
                resource_type="website",
                resource_id=website.id,
                result=AdminActionResult.SUCCESS,
                details={"task_id": task.id},
            )
        else:
            record_admin_action(
                admin=None,
                action=f"agent_{task.task_type.value}_failed",
                resource_type="website",
                resource_id=website.id,
                result=AdminActionResult.FAILURE,
                details={"task_id": task.id, "error": task.error},
            )
        db.session.commit()
    return True
