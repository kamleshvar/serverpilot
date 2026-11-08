"""Website configuration and lifecycle rules (ownership and quotas enforced)."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from flask import current_app
from sqlalchemy.exc import IntegrityError

from ..errors import (
    AgentUnavailable,
    ConflictError,
    IntegrationNotConfigured,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from ..extensions import db
from ..models import (
    Domain,
    Framework,
    GithubInstallation,
    User,
    Website,
    WebsiteStatus,
)
from ..models.base import new_uuid
from ..utils import utcnow, validate_subdomain
from .audit import record_user_activity
from .domains import resolve_domain_for_user
from .quota import QuotaSnapshot, assert_can_create_website, quota_snapshot

logger = logging.getLogger(__name__)

EDITABLE_STATUSES = {
    WebsiteStatus.PENDING,
    WebsiteStatus.USER_STOPPED,
    WebsiteStatus.ADMIN_FORCED_STOP,
    WebsiteStatus.QUOTA_STOPPED,
    WebsiteStatus.FAILED,
}
ACTIVE_DEPLOYMENT_STATUSES = {
    "queued",
    "building",
    "deploying",
    "health_check",
}
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_HEALTH_PATH_RE = re.compile(r"^/[^\s]{0,254}$")


@dataclass
class WebsiteInput:
    name: str
    subdomain: str
    domain_name: str
    repository_full_name: str
    branch: str
    framework: Framework
    build_command: str | None = None
    start_command: str | None = None
    root_directory: str = ""
    internal_port: int = 8000
    healthcheck_path: str = "/"
    ram_limit_mb: int | None = None
    storage_limit_mb: int | None = None
    cpu_limit: float | None = None
    auto_deploy_enabled: bool = False


def owned_website(user: User, website_id: str) -> Website:
    website = db.session.get(Website, website_id)
    if website is None or website.status == WebsiteStatus.DELETED:
        raise NotFoundError("Website not found.")
    if website.owner_id != user.id and not user.is_admin:
        raise PermissionDenied("You do not have access to this website.")
    return website


def _clean_text(
    value: str | None, *, label: str, max_length: int, required: bool = False
) -> str | None:
    cleaned = (value or "").strip()
    if required and not cleaned:
        raise ValidationError(f"{label} is required.")
    if len(cleaned) > max_length:
        raise ValidationError(f"{label} must be at most {max_length} characters.")
    if "\x00" in cleaned:
        raise ValidationError(f"{label} contains an invalid character.")
    return cleaned or None


def _validate_input(payload: WebsiteInput) -> None:
    name = (payload.name or "").strip()
    if not _NAME_RE.match(name):
        raise ValidationError("Website name must be 1-120 printable characters.")
    branch = (payload.branch or "").strip()
    if not _BRANCH_RE.match(branch) or ".." in branch:
        raise ValidationError("Branch name is invalid.")
    if not _HEALTH_PATH_RE.match((payload.healthcheck_path or "").strip()):
        raise ValidationError(
            "Health check path must start with '/' and contain no spaces."
        )
    if not (1 <= int(payload.internal_port) <= 65535):
        raise ValidationError("Internal port must be between 1 and 65535.")
    root = (payload.root_directory or "").strip().strip("/")
    if root:
        if any(part in {"..", "."} for part in root.split("/")):
            raise ValidationError(
                "Root directory must be a path inside the repository."
            )
        if len(root) > 255:
            raise ValidationError("Root directory is too long.")
    for raw, label, maximum in (
        (payload.build_command, "Build command", 4000),
        (payload.start_command, "Start command", 4000),
    ):
        if raw and len(raw) > maximum:
            raise ValidationError(f"{label} is too long.")
        if raw and "\x00" in raw:
            raise ValidationError(f"{label} contains an invalid character.")


def _sync_cloudflare_website(
    website: Website,
    *,
    previous_domain: Domain | None = None,
    previous_fqdn: str | None = None,
) -> None:
    from .audit import notify_admins
    from .cloudflare import (
        CloudflareError,
        cloudflare_configured,
        delete_dns_record,
        ensure_website_dns,
    )

    if not cloudflare_configured():
        return
    try:
        if (
            previous_domain is not None
            and previous_fqdn
            and (
                previous_fqdn != website.fqdn or previous_domain.id != website.domain_id
            )
        ):
            delete_dns_record(previous_domain, previous_fqdn, commit=True)
        ensure_website_dns(website, commit=True)
    except (CloudflareError, IntegrationNotConfigured) as exc:
        db.session.rollback()
        notify_admins(
            category="cloudflare_sync_failed",
            title="Cloudflare DNS synchronization failed",
            body=exc.message,
            dedupe_key=f"cloudflare-sync:{website.id}",
            details={"website_id": website.id, "fqdn": website.fqdn},
            commit=True,
        )
        logger.warning(
            "Cloudflare DNS synchronization failed website_id=%s error=%s",
            website.id,
            exc.message,
        )


def create_website(
    user: User,
    payload: WebsiteInput,
    *,
    github_installation: GithubInstallation | None = None,
    repository_default_branch: str,
) -> Website:
    _validate_input(payload)
    domain = resolve_domain_for_user(user, payload.domain_name)
    subdomain = validate_subdomain(payload.subdomain)
    fqdn = f"{subdomain}.{domain.name}".lower()

    ram = payload.ram_limit_mb or current_app.config["DEFAULT_WEBSITE_RAM_MB"]
    storage = (
        payload.storage_limit_mb or current_app.config["DEFAULT_WEBSITE_STORAGE_MB"]
    )
    cpu = payload.cpu_limit or current_app.config["DEFAULT_WEBSITE_CPU"]

    snapshot = assert_can_create_website(
        user, ram_limit_mb=ram, storage_limit_mb=storage, cpu_limit=cpu
    )

    if (
        Website.query.filter(
            Website.fqdn == fqdn,
            Website.status != WebsiteStatus.DELETED,
        ).first()
        is not None
    ):
        raise ConflictError("That subdomain is already in use.")

    if github_installation is not None:
        if github_installation.user_id != user.id and not user.is_admin:
            raise PermissionDenied(
                "The GitHub installation is not connected to your account."
            )
        if github_installation.status.value != "active":
            raise ValidationError("The GitHub App installation is not active.")

    website = Website(
        owner_id=user.id,
        domain_id=domain.id,
        name=payload.name.strip(),
        subdomain=subdomain,
        fqdn=fqdn,
        status=WebsiteStatus.PENDING,
        status_detail="Waiting for the first deployment.",
        github_installation_id=github_installation.id if github_installation else None,
        repository_full_name=payload.repository_full_name.strip(),
        branch=(payload.branch or repository_default_branch or "main").strip(),
        root_directory=(payload.root_directory or "").strip().strip("/"),
        framework=payload.framework,
        build_command=_clean_text(
            payload.build_command, label="Build command", max_length=4000
        ),
        start_command=_clean_text(
            payload.start_command, label="Start command", max_length=4000
        ),
        internal_port=int(payload.internal_port),
        healthcheck_path=(payload.healthcheck_path or "/").strip(),
        ram_limit_mb=int(ram),
        storage_limit_mb=int(storage),
        cpu_limit=float(cpu),
        auto_deploy_enabled=bool(payload.auto_deploy_enabled),
        build_config={
            "source": "github_app" if github_installation else "github_oauth",
        },
    )
    db.session.add(website)
    db.session.flush()
    website.container_name = f"sp-{website.id.replace('-', '')[:24]}"
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise ConflictError(
            "That website name or subdomain was just claimed. Choose another."
        ) from exc

    record_user_activity(
        user=user,
        action="website_created",
        resource_type="website",
        resource_id=website.id,
        description=f"Created website {website.fqdn}",
        details={"quota_usage": snapshot.websites_used + 1},
        commit=True,
    )
    logger.info("Website %s created by user %s", website.fqdn, user.email)
    _sync_cloudflare_website(website)
    return website


def update_website(
    user: User,
    website: Website,
    payload: WebsiteInput,
) -> Website:
    if website.owner_id != user.id and not user.is_admin:
        raise PermissionDenied("You do not have access to this website.")
    if website.status not in EDITABLE_STATUSES:
        raise ConflictError(
            "Stop the website before changing its source or domain configuration."
        )
    if website.is_admin_stopped and not user.is_admin:
        raise PermissionDenied("This website is locked by an administrator.")
    _validate_input(payload)

    domain = resolve_domain_for_user(user, payload.domain_name)
    subdomain = validate_subdomain(payload.subdomain)
    fqdn = f"{subdomain}.{domain.name}".lower()
    duplicate = Website.query.filter(
        Website.fqdn == fqdn,
        Website.id != website.id,
        Website.status != WebsiteStatus.DELETED,
    ).first()
    if duplicate is not None:
        raise ConflictError("That subdomain is already in use.")

    if payload.repository_full_name != website.repository_full_name:
        raise ValidationError(
            "Repository changes must be made by reconnecting the source in a new "
            "deployment. Other configuration can be updated here."
        )

    previous_domain = website.domain
    previous_fqdn = website.fqdn
    website.name = payload.name.strip()
    website.subdomain = subdomain
    website.domain_id = domain.id
    website.fqdn = fqdn
    website.branch = (payload.branch or website.branch).strip()
    website.root_directory = (payload.root_directory or "").strip().strip("/")
    website.framework = payload.framework
    website.build_command = _clean_text(
        payload.build_command, label="Build command", max_length=4000
    )
    website.start_command = _clean_text(
        payload.start_command, label="Start command", max_length=4000
    )
    website.internal_port = int(payload.internal_port)
    website.healthcheck_path = (payload.healthcheck_path or "/").strip()
    website.auto_deploy_enabled = bool(payload.auto_deploy_enabled)
    website.touch()
    db.session.commit()
    record_user_activity(
        user=user,
        action="website_updated",
        resource_type="website",
        resource_id=website.id,
        description=f"Updated website {website.fqdn}",
        commit=True,
    )
    _sync_cloudflare_website(
        website,
        previous_domain=previous_domain,
        previous_fqdn=previous_fqdn,
    )
    return website


def _delete_cloudflare_website(website: Website, fqdn: str, domain: Domain) -> None:
    from .audit import notify_admins
    from .cloudflare import CloudflareError, cloudflare_configured, delete_dns_record

    if not cloudflare_configured():
        return
    try:
        delete_dns_record(domain, fqdn, commit=True)
    except (CloudflareError, IntegrationNotConfigured) as exc:
        db.session.rollback()
        notify_admins(
            category="cloudflare_sync_failed",
            title="Cloudflare DNS cleanup failed",
            body=exc.message,
            dedupe_key=f"cloudflare-delete:{website.id}",
            details={"website_id": website.id, "fqdn": fqdn},
            commit=True,
        )
        logger.warning(
            "Cloudflare DNS cleanup failed website_id=%s error=%s",
            website.id,
            exc.message,
        )


def delete_website(user: User, website: Website, *, reason: str | None = None) -> None:
    if website.owner_id != user.id and not user.is_admin:
        raise PermissionDenied("You do not have access to this website.")
    if website.is_admin_stopped and not user.is_admin:
        raise PermissionDenied("This website is locked by an administrator.")
    if website.status in {WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}:
        raise ConflictError(
            "Stop the website and wait for the agent to confirm before deleting it."
        )
    if website.deployments:
        from ..models import Deployment, DeploymentStatus

        active = Deployment.query.filter(
            Deployment.website_id == website.id,
            Deployment.status.in_(
                [
                    DeploymentStatus.QUEUED,
                    DeploymentStatus.BUILDING,
                    DeploymentStatus.DEPLOYING,
                    DeploymentStatus.HEALTH_CHECK,
                ]
            ),
        ).count()
        if active:
            raise ConflictError("A deployment is still in progress.")

    from ..models import AgentTaskPriority, TaskType
    from .agent_tasks import active_task, enqueue_task, select_agent

    if active_task(website):
        raise ConflictError("A website operation is still in progress.")
    if website.current_deployment_id and website.container_name:
        agent = select_agent(website)
        enqueue_task(
            agent=agent,
            task_type=TaskType.DELETE,
            website=website,
            payload={
                "website_id": website.id,
                "container_name": website.container_name,
                "fqdn": website.fqdn,
            },
            created_by_id=user.id,
            priority=AgentTaskPriority.HIGH,
            idempotency_key=f"delete:{website.id}",
            max_attempts=1,
        )

    original_fqdn = website.fqdn
    original_domain = website.domain
    website.status = WebsiteStatus.DELETED
    website.deleted_at = utcnow()
    website.deleted_by_id = user.id
    website.delete_reason = (reason or "Deleted by account owner")[:4000]
    website.container_name = None
    archive_slug = f"deleted-{new_uuid()}"
    website.subdomain = archive_slug[:63]
    website.fqdn = f"{archive_slug}.{website.domain.name}"[:253]
    website.touch()
    db.session.commit()
    record_user_activity(
        user=user,
        action="website_deleted",
        resource_type="website",
        resource_id=website.id,
        description=f"Deleted website {original_fqdn}",
        commit=True,
    )
    logger.info("Website %s deleted by %s", original_fqdn, user.email)
    _delete_cloudflare_website(website, original_fqdn, original_domain)


def require_available_agent() -> None:
    """Raise until a real, healthy agent is registered and connected."""
    from ..models import (
        AgentStatus,
        Server,
        ServerAgent,
        ServerApprovalStatus,
        ServerStatus,
    )

    agent = (
        ServerAgent.query.join(Server)
        .filter(
            ServerAgent.status == AgentStatus.ACTIVE,
            Server.status == ServerStatus.ONLINE,
            Server.approval_status == ServerApprovalStatus.APPROVED,
            Server.deleted_at.is_(None),
        )
        .first()
    )
    if agent is None or not agent.is_online or not agent.server.is_healthy:
        raise AgentUnavailable(
            "No healthy deployment agent is connected. Ask the platform operator "
            "to complete the agent installation."
        )


def assert_website_can_start(user: User, website: Website) -> QuotaSnapshot:
    if website.is_admin_stopped or website.forced_stop_at is not None:
        raise PermissionDenied(
            "This website was stopped by an administrator and cannot be restarted "
            "from the user panel."
        )
    if website.maintenance_enabled:
        raise ConflictError("This website is in platform maintenance mode.")
    from .quota import assert_website_ram_available

    snapshot = assert_website_ram_available(user, website)
    require_available_agent()
    return snapshot


def quota_for_user(user: User) -> QuotaSnapshot:
    return quota_snapshot(user)
