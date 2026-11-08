"""Website ownership, lifecycle, deployment history and containers."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from ..extensions import db
from ..utils import utcnow
from .base import BaseModel, TimestampMixin, UUIDMixin, sa_enum
from .enums import (
    ContainerStatus,
    DeploymentStatus,
    DeploymentTrigger,
    Framework,
    InitiatorType,
    LogLevel,
    LogSource,
    StopReason,
    WebsiteStatus,
)

if TYPE_CHECKING:
    from .dns import DnsRecord
    from .github import GithubInstallation
    from .infrastructure import AgentTask, Domain, Server
    from .operations import Backup, MaintenanceWindow
    from .secrets import EnvironmentVariable
    from .user import User


class Website(BaseModel):
    __tablename__ = "websites"
    __table_args__ = (
        UniqueConstraint("domain_id", "subdomain", name="uq_website_domain_subdomain"),
        CheckConstraint("ram_limit_mb > 0", name="websites_ram_positive"),
        CheckConstraint("storage_limit_mb > 0", name="websites_storage_positive"),
        CheckConstraint("cpu_limit > 0", name="websites_cpu_positive"),
        CheckConstraint("internal_port > 0", name="websites_port_positive"),
        Index("ix_websites_owner_status", "owner_id", "status"),
        Index("ix_websites_domain_status", "domain_id", "status"),
        Index("ix_websites_status_updated", "status", "updated_at"),
    )

    owner_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    domain_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("domains.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("servers.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    subdomain: Mapped[str] = mapped_column(String(63), nullable=False)
    fqdn: Mapped[str] = mapped_column(
        String(253), nullable=False, unique=True, index=True
    )
    status: Mapped[WebsiteStatus] = mapped_column(
        sa_enum(WebsiteStatus),
        nullable=False,
        default=WebsiteStatus.PENDING,
        index=True,
    )
    status_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    status_detail: Mapped[str | None] = mapped_column(Text)
    stop_reason: Mapped[StopReason | None] = mapped_column(sa_enum(StopReason))
    stop_detail: Mapped[str | None] = mapped_column(Text)

    # Source / build configuration
    github_installation_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("github_installations.id", ondelete="SET NULL"),
        index=True,
    )
    repository_full_name: Mapped[str | None] = mapped_column(String(255))
    repository_id: Mapped[int | None] = mapped_column(BigInteger)
    branch: Mapped[str] = mapped_column(String(255), default="main", nullable=False)
    root_directory: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    framework: Mapped[Framework] = mapped_column(
        sa_enum(Framework), nullable=False, default=Framework.OTHER
    )
    build_command: Mapped[str | None] = mapped_column(Text)
    start_command: Mapped[str | None] = mapped_column(Text)
    dockerfile_path: Mapped[str | None] = mapped_column(String(255))
    build_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    auto_deploy_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Runtime configuration
    container_name: Mapped[str | None] = mapped_column(String(120), unique=True)
    image_tag: Mapped[str | None] = mapped_column(String(255))
    internal_port: Mapped[int] = mapped_column(Integer, default=8000, nullable=False)
    cpu_limit: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    ram_limit_mb: Mapped[int] = mapped_column(Integer, default=256, nullable=False)
    storage_limit_mb: Mapped[int] = mapped_column(Integer, default=1024, nullable=False)
    healthcheck_path: Mapped[str] = mapped_column(
        String(255), default="/", nullable=False
    )
    healthcheck_timeout_seconds: Mapped[int] = mapped_column(
        Integer, default=60, nullable=False
    )

    # Current deployment is intentionally not a hard FK to avoid a circular
    # constraint during table creation and restore operations. Services verify it.
    current_deployment_id: Mapped[str | None] = mapped_column(String(36), index=True)
    last_deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    # Administrative controls
    maintenance_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    maintenance_message: Mapped[str | None] = mapped_column(Text)
    maintenance_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    forced_stop_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    forced_stop_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    forced_stop_reason: Mapped[str | None] = mapped_column(Text)
    quota_stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    admin_notes: Mapped[str | None] = mapped_column(Text)

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    delete_reason: Mapped[str | None] = mapped_column(Text)

    owner: Mapped[User] = relationship(
        back_populates="websites", foreign_keys=[owner_id]
    )
    forced_stop_by: Mapped[User | None] = relationship(foreign_keys=[forced_stop_by_id])
    deleted_by: Mapped[User | None] = relationship(foreign_keys=[deleted_by_id])
    domain: Mapped[Domain] = relationship(back_populates="websites")
    server: Mapped[Server | None] = relationship(back_populates="websites")
    github_installation: Mapped[GithubInstallation | None] = relationship(
        back_populates="websites", foreign_keys=[github_installation_id]
    )
    deployments: Mapped[list[Deployment]] = relationship(
        back_populates="website",
        foreign_keys="Deployment.website_id",
        order_by="Deployment.created_at.desc()",
    )
    environment_variables: Mapped[list[EnvironmentVariable]] = relationship(
        back_populates="website", cascade="all, delete-orphan"
    )
    dns_records: Mapped[list[DnsRecord]] = relationship(back_populates="website")
    backups: Mapped[list[Backup]] = relationship(back_populates="website")
    container: Mapped[Container | None] = relationship(
        back_populates="website", uselist=False, cascade="all, delete-orphan"
    )
    maintenance_windows: Mapped[list[MaintenanceWindow]] = relationship(
        back_populates="website", cascade="all, delete-orphan"
    )

    @validates("subdomain")
    def _normalize_subdomain(self, _key: str, value: str) -> str:
        return (value or "").strip().lower()

    @validates("fqdn")
    def _normalize_fqdn(self, _key: str, value: str) -> str:
        return (value or "").strip().lower().rstrip(".")

    @property
    def url(self) -> str:
        return f"https://{self.fqdn}"

    @property
    def is_deleted(self) -> bool:
        return self.status == WebsiteStatus.DELETED or self.deleted_at is not None

    @property
    def is_admin_stopped(self) -> bool:
        return (
            self.status == WebsiteStatus.ADMIN_FORCED_STOP
            or self.forced_stop_at is not None
        )

    @property
    def is_running(self) -> bool:
        return self.status == WebsiteStatus.RUNNING

    @property
    def can_receive_traffic(self) -> bool:
        return self.is_running and not self.maintenance_enabled

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Website {self.fqdn} {self.status.value}>"


class Deployment(BaseModel):
    __tablename__ = "deployments"
    __table_args__ = (
        UniqueConstraint("website_id", "number", name="uq_deployment_website_number"),
        Index("ix_deployments_website_created", "website_id", "created_at"),
        Index("ix_deployments_status_created", "status", "created_at"),
        Index("ix_deployments_current", "website_id", "is_current"),
    )

    website_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    initiated_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    initiator_type: Mapped[InitiatorType] = mapped_column(
        sa_enum(InitiatorType), nullable=False, default=InitiatorType.USER
    )
    trigger: Mapped[DeploymentTrigger] = mapped_column(
        sa_enum(DeploymentTrigger), nullable=False, default=DeploymentTrigger.MANUAL
    )
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[DeploymentStatus] = mapped_column(
        sa_enum(DeploymentStatus),
        nullable=False,
        default=DeploymentStatus.QUEUED,
        index=True,
    )
    repository_full_name: Mapped[str | None] = mapped_column(String(255))
    branch: Mapped[str | None] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    commit_message: Mapped[str | None] = mapped_column(Text)
    commit_author: Mapped[str | None] = mapped_column(String(255))
    source_ref: Mapped[str | None] = mapped_column(String(255))
    image_tag: Mapped[str | None] = mapped_column(String(255))
    artifact_path: Mapped[str | None] = mapped_column(String(1024))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rollback_of_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("deployments.id", ondelete="SET NULL")
    )
    failure_reason: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(64))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_retained: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    website: Mapped[Website] = relationship(
        back_populates="deployments", foreign_keys=[website_id]
    )
    user: Mapped[User] = relationship(foreign_keys=[user_id])
    initiated_by: Mapped[User | None] = relationship(foreign_keys=[initiated_by_id])
    rollback_of: Mapped[Deployment | None] = relationship(
        remote_side="Deployment.id", foreign_keys=[rollback_of_id]
    )
    logs: Mapped[list[DeploymentLog]] = relationship(
        back_populates="deployment",
        cascade="all, delete-orphan",
        order_by="DeploymentLog.sequence",
    )
    agent_tasks: Mapped[list[AgentTask]] = relationship(
        back_populates="deployment", foreign_keys="AgentTask.deployment_id"
    )

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            DeploymentStatus.SUCCEEDED,
            DeploymentStatus.FAILED,
            DeploymentStatus.CANCELLED,
            DeploymentStatus.ROLLED_BACK,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Deployment {self.website_id}#{self.number} {self.status.value}>"


class DeploymentLog(db.Model):
    __tablename__ = "deployment_logs"
    __table_args__ = (
        UniqueConstraint("deployment_id", "sequence", name="uq_deployment_log_seq"),
        Index("ix_deployment_logs_deployment_created", "deployment_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    deployment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("deployments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[LogSource] = mapped_column(
        sa_enum(LogSource), nullable=False, default=LogSource.DEPLOYMENT
    )
    level: Mapped[LogLevel] = mapped_column(
        sa_enum(LogLevel), nullable=False, default=LogLevel.INFO
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_redacted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    deployment: Mapped[Deployment] = relationship(back_populates="logs")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DeploymentLog {self.deployment_id}#{self.sequence}>"


class Container(UUIDMixin, TimestampMixin, db.Model):
    __tablename__ = "containers"
    __table_args__ = (
        CheckConstraint("ram_limit_mb > 0", name="containers_ram_positive"),
        CheckConstraint("storage_limit_mb > 0", name="containers_storage_positive"),
        Index("ix_containers_server_status", "server_id", "status"),
    )

    website_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("servers.id", ondelete="SET NULL"), index=True
    )
    docker_container_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    image: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[ContainerStatus] = mapped_column(
        sa_enum(ContainerStatus),
        nullable=False,
        default=ContainerStatus.CREATED,
        index=True,
    )
    health_status: Mapped[str | None] = mapped_column(String(32))
    internal_port: Mapped[int] = mapped_column(Integer, nullable=False, default=8000)
    cpu_limit: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    ram_limit_mb: Mapped[int] = mapped_column(Integer, default=256, nullable=False)
    storage_limit_mb: Mapped[int] = mapped_column(Integer, default=1024, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    restart_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_cpu_percent: Mapped[float | None] = mapped_column(Float)
    last_ram_mb: Mapped[float | None] = mapped_column(Float)
    last_storage_mb: Mapped[float | None] = mapped_column(Float)

    website: Mapped[Website] = relationship(back_populates="container")
    server: Mapped[Server | None] = relationship(back_populates="containers")
