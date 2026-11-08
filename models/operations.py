"""Monitoring, notifications, backups, audit trails and platform settings."""

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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from ..utils import utcnow
from .base import BaseModel, TimestampMixin, UUIDMixin, sa_enum
from .enums import (
    AdminActionResult,
    BackupScope,
    BackupStatus,
    NotificationAudience,
    ResourceScope,
    Severity,
)

if TYPE_CHECKING:
    from .infrastructure import Server
    from .user import User
    from .website import Website


class ResourceUsage(db.Model):
    __tablename__ = "resource_usage"
    __table_args__ = (
        CheckConstraint("cpu_percent >= 0", name="resource_usage_cpu_nonnegative"),
        CheckConstraint("ram_mb >= 0", name="resource_usage_ram_nonnegative"),
        CheckConstraint("storage_mb >= 0", name="resource_usage_storage_nonnegative"),
        Index(
            "ix_resource_usage_scope_subject_time", "scope", "subject_id", "recorded_at"
        ),
        Index("ix_resource_usage_user_time", "user_id", "recorded_at"),
        Index("ix_resource_usage_website_time", "website_id", "recorded_at"),
        Index("ix_resource_usage_server_time", "server_id", "recorded_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    scope: Mapped[ResourceScope] = mapped_column(
        sa_enum(ResourceScope), nullable=False, index=True
    )
    subject_id: Mapped[str | None] = mapped_column(String(36), index=True)
    server_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("servers.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    website_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("websites.id", ondelete="SET NULL"), index=True
    )
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ram_mb: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    storage_mb: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    container_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    source: Mapped[str] = mapped_column(String(32), default="agent", nullable=False)

    server: Mapped[Server | None] = relationship(back_populates="resource_samples")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ResourceUsage {self.scope.value}:{self.subject_id}>"


class Backup(BaseModel):
    __tablename__ = "backups"
    __table_args__ = (
        Index("ix_backups_website_created", "website_id", "created_at"),
        Index("ix_backups_status_expires", "status", "expires_at"),
    )

    scope: Mapped[BackupScope] = mapped_column(sa_enum(BackupScope), nullable=False)
    website_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("websites.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[BackupStatus] = mapped_column(
        sa_enum(BackupStatus), nullable=False, default=BackupStatus.PENDING, index=True
    )
    storage_path: Mapped[str | None] = mapped_column(String(1024))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    checksum_sha256: Mapped[str | None] = mapped_column(String(64))
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    restored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    restore_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    website: Mapped[Website | None] = relationship(back_populates="backups")
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id])

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Backup {self.id} {self.scope.value} {self.status.value}>"


class Notification(BaseModel):
    __tablename__ = "notifications"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_notifications_dedupe_key"),
        Index("ix_notifications_user_unread", "user_id", "is_read", "created_at"),
        Index("ix_notifications_audience_created", "audience", "created_at"),
    )

    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    audience: Mapped[NotificationAudience] = mapped_column(
        sa_enum(NotificationAudience), nullable=False, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        sa_enum(Severity), nullable=False, default=Severity.INFO
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    link: Mapped[str | None] = mapped_column(String(1024))
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dedupe_key: Mapped[str | None] = mapped_column(String(191))
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    user: Mapped[User | None] = relationship(back_populates="notifications")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Notification {self.category} {self.title!r}>"


class UserActivity(db.Model):
    __tablename__ = "user_activity"
    __table_args__ = (
        Index("ix_user_activity_user_created", "user_id", "created_at"),
        Index("ix_user_activity_action_created", "action", "created_at"),
        Index("ix_user_activity_resource", "resource_type", "resource_id"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(512))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    user: Mapped[User | None] = relationship(back_populates="activities")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<UserActivity {self.action}>"


class AdminAction(db.Model):
    __tablename__ = "admin_actions"
    __table_args__ = (
        Index("ix_admin_actions_admin_created", "admin_user_id", "created_at"),
        Index("ix_admin_actions_resource", "resource_type", "resource_id"),
        Index("ix_admin_actions_action_created", "action", "created_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    admin_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    admin_email: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[AdminActionResult] = mapped_column(
        sa_enum(AdminActionResult), nullable=False, default=AdminActionResult.SUCCESS
    )
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    admin: Mapped[User | None] = relationship(back_populates="admin_actions")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AdminAction {self.action} {self.result.value}>"


class MaintenanceWindow(BaseModel):
    __tablename__ = "maintenance_windows"
    __table_args__ = (Index("ix_maintenance_windows_time", "starts_at", "ends_at"),)

    website_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("websites.id", ondelete="CASCADE"), index=True
    )
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    website: Mapped[Website | None] = relationship(back_populates="maintenance_windows")
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id])


class AuthAttempt(db.Model):
    __tablename__ = "auth_attempts"
    __table_args__ = (
        Index("ix_auth_attempts_ip_created", "ip_address", "created_at"),
        Index("ix_auth_attempts_provider_created", "provider", "created_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    identifier: Mapped[str | None] = mapped_column(String(320))
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class PlatformSetting(UUIDMixin, TimestampMixin, db.Model):
    __tablename__ = "platform_settings"

    key: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True
    )
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON)
    description: Mapped[str | None] = mapped_column(String(255))
    updated_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    updated_by: Mapped[User | None] = relationship(foreign_keys=[updated_by_id])
