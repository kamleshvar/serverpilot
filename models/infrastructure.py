"""Domains, servers, secure agent identity and signed task queue."""

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
    AgentInstallStatus,
    AgentStatus,
    AgentTaskPriority,
    DnsStatus,
    DomainStatus,
    ScanStatus,
    ServerApprovalStatus,
    ServerConnectionStatus,
    ServerStatus,
    TaskStatus,
    TaskType,
)

if TYPE_CHECKING:
    from .dns import DnsRecord
    from .website import Container, Deployment, ResourceUsage, Website


class Domain(BaseModel):
    __tablename__ = "domains"
    __table_args__ = (
        Index("ix_domains_status_user_allowed", "status", "is_user_allowed"),
    )

    name: Mapped[str] = mapped_column(
        String(253), nullable=False, unique=True, index=True
    )
    is_user_allowed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )
    cloudflare_zone_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    cloudflare_zone_name: Mapped[str | None] = mapped_column(String(253))
    status: Mapped[DomainStatus] = mapped_column(
        sa_enum(DomainStatus), nullable=False, default=DomainStatus.PENDING
    )
    dns_status: Mapped[DnsStatus] = mapped_column(
        sa_enum(DnsStatus), nullable=False, default=DnsStatus.UNKNOWN
    )
    last_dns_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dns_last_error: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)

    websites: Mapped[list[Website]] = relationship(back_populates="domain")
    dns_records: Mapped[list[DnsRecord]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )

    @validates("name", "cloudflare_zone_name")
    def _normalize_name(self, _key: str, value: str | None) -> str | None:
        return value.strip().lower().rstrip(".") if value else value

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Domain {self.name}>"


class Server(BaseModel):
    __tablename__ = "servers"
    __table_args__ = (
        CheckConstraint("total_ram_mb > 0", name="servers_ram_positive"),
        CheckConstraint("total_storage_mb > 0", name="servers_storage_positive"),
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True)
    ssh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    ssh_username: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ubuntu"
    )
    region: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    status: Mapped[ServerStatus] = mapped_column(
        sa_enum(ServerStatus), nullable=False, default=ServerStatus.PROVISIONING
    )
    approval_status: Mapped[ServerApprovalStatus] = mapped_column(
        sa_enum(ServerApprovalStatus),
        nullable=False,
        default=ServerApprovalStatus.PENDING,
        index=True,
    )
    connection_status: Mapped[ServerConnectionStatus] = mapped_column(
        sa_enum(ServerConnectionStatus),
        nullable=False,
        default=ServerConnectionStatus.UNKNOWN,
    )
    scan_status: Mapped[ScanStatus] = mapped_column(
        sa_enum(ScanStatus), nullable=False, default=ScanStatus.PENDING
    )
    agent_install_status: Mapped[AgentInstallStatus] = mapped_column(
        sa_enum(AgentInstallStatus),
        nullable=False,
        default=AgentInstallStatus.NOT_INSTALLED,
    )
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    total_ram_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=2048)
    total_storage_mb: Mapped[int] = mapped_column(
        Integer, nullable=False, default=40960
    )
    total_cpu_cores: Mapped[float] = mapped_column(Float, nullable=False, default=2.0)
    reserved_ram_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=128)
    operating_system: Mapped[str | None] = mapped_column(String(120))
    os_version: Mapped[str | None] = mapped_column(String(120))
    kernel_version: Mapped[str | None] = mapped_column(String(120))
    cpu_model: Mapped[str | None] = mapped_column(String(255))
    docker_version: Mapped[str | None] = mapped_column(String(64))
    docker_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    nginx_version: Mapped[str | None] = mapped_column(String(64))
    nginx_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(255))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_error: Mapped[str | None] = mapped_column(Text)
    last_ssh_connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_error: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    deleted_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    agents: Mapped[list[ServerAgent]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )
    websites: Mapped[list[Website]] = relationship(back_populates="server")
    containers: Mapped[list[Container]] = relationship(back_populates="server")
    resource_samples: Mapped[list[ResourceUsage]] = relationship(
        back_populates="server"
    )
    scans: Mapped[list[ServerScan]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )
    resource_history: Mapped[list[ServerResourceHistory]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )
    enrollments: Mapped[list[AgentEnrollment]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )

    @property
    def is_healthy(self) -> bool:
        if self.status != ServerStatus.ONLINE:
            return False
        if not self.last_heartbeat_at:
            return False
        last = self.last_heartbeat_at
        if last.tzinfo is None:
            return (utcnow().replace(tzinfo=None) - last).total_seconds() < 180
        return (utcnow() - last).total_seconds() < 180

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Server {self.name} {self.status.value}>"


class ServerAgent(BaseModel):
    __tablename__ = "server_agents"
    __table_args__ = (Index("ix_server_agents_status_seen", "status", "last_seen_at"),)

    server_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("servers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    agent_uid: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    status: Mapped[AgentStatus] = mapped_column(
        sa_enum(AgentStatus), nullable=False, default=AgentStatus.PENDING
    )
    version: Mapped[str | None] = mapped_column(String(32))
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(Text)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    server: Mapped[Server] = relationship(back_populates="agents")
    credentials: Mapped[list[AgentCredential]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )
    tasks: Mapped[list[AgentTask]] = relationship(back_populates="agent")

    @property
    def is_online(self) -> bool:
        if self.status != AgentStatus.ACTIVE or not self.last_seen_at:
            return False
        last = self.last_seen_at
        if last.tzinfo is None:
            return (utcnow().replace(tzinfo=None) - last).total_seconds() < 180
        return (utcnow() - last).total_seconds() < 180

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ServerAgent {self.name} {self.status.value}>"


class ServerScan(BaseModel):
    __tablename__ = "server_scans"
    __table_args__ = (Index("ix_server_scans_server_time", "server_id", "scanned_at"),)

    server_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("servers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanned_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    status: Mapped[ScanStatus] = mapped_column(
        sa_enum(ScanStatus), nullable=False, default=ScanStatus.SUCCEEDED
    )
    scan_results: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    warnings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    errors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    server: Mapped[Server] = relationship(back_populates="scans")


class ServerResourceHistory(db.Model):
    __tablename__ = "server_resource_history"
    __table_args__ = (
        Index("ix_server_resource_history_server_time", "server_id", "recorded_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    server_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("servers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ram_usage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    storage_usage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    server: Mapped[Server] = relationship(back_populates="resource_history")


class AgentEnrollment(UUIDMixin, TimestampMixin, db.Model):
    __tablename__ = "agent_enrollments"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_agent_enrollments_token_hash"),
        Index("ix_agent_enrollments_expires", "expires_at"),
    )

    server_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("servers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by_agent_uid: Mapped[str | None] = mapped_column(String(64))

    server: Mapped[Server] = relationship(back_populates="enrollments")


class AgentCredential(UUIDMixin, TimestampMixin, db.Model):
    __tablename__ = "agent_credentials"

    agent_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("server_agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    agent: Mapped[ServerAgent] = relationship(back_populates="credentials")

    @property
    def is_valid(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is None:
            return True
        now = utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            now = now.replace(tzinfo=None)
        return expires > now


class AgentNonce(UUIDMixin, db.Model):
    __tablename__ = "agent_nonces"
    __table_args__ = (
        UniqueConstraint("key_id", "nonce", name="uq_agent_nonce_key"),
        Index("ix_agent_nonces_expires", "expires_at"),
    )

    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AgentTask(BaseModel):
    __tablename__ = "agent_tasks"
    __table_args__ = (
        Index("ix_agent_tasks_agent_status", "agent_id", "status", "created_at"),
        UniqueConstraint("idempotency_key", name="uq_agent_tasks_idempotency_key"),
        CheckConstraint("attempts >= 0", name="agent_tasks_attempts_nonnegative"),
    )

    agent_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("server_agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    website_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("websites.id", ondelete="SET NULL"), index=True
    )
    deployment_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("deployments.id", ondelete="SET NULL"), index=True
    )
    task_type: Mapped[TaskType] = mapped_column(sa_enum(TaskType), nullable=False)
    status: Mapped[TaskStatus] = mapped_column(
        sa_enum(TaskStatus), nullable=False, default=TaskStatus.PENDING, index=True
    )
    priority: Mapped[AgentTaskPriority] = mapped_column(
        sa_enum(AgentTaskPriority),
        nullable=False,
        default=AgentTaskPriority.NORMAL,
    )
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    agent: Mapped[ServerAgent] = relationship(back_populates="tasks")
    website: Mapped[Website | None] = relationship(foreign_keys=[website_id])
    deployment: Mapped[Deployment | None] = relationship(
        back_populates="agent_tasks", foreign_keys=[deployment_id]
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AgentTask {self.task_type.value} {self.status.value}>"
