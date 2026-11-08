"""Users, linked OAuth identities, sessions and per-user quotas."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
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
from .enums import IdentityProvider, UserRole, UserStatus

if TYPE_CHECKING:
    from .github import GithubInstallation
    from .operations import AdminAction, Notification, UserActivity
    from .website import Website


class User(BaseModel):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_status_role", "status", "role"),
        Index("ix_users_created_at", "created_at"),
    )

    email: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True, index=True
    )
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    avatar_url: Mapped[str | None] = mapped_column(String(1024))
    role: Mapped[UserRole] = mapped_column(
        sa_enum(UserRole), nullable=False, default=UserRole.USER, index=True
    )
    status: Mapped[UserStatus] = mapped_column(
        sa_enum(UserStatus), nullable=False, default=UserStatus.ACTIVE, index=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suspension_reason: Mapped[str | None] = mapped_column(Text)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", nullable=False)

    quota: Mapped[UserQuota | None] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
        foreign_keys="UserQuota.user_id",
    )
    identities: Mapped[list[UserIdentity]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="UserIdentity.created_at",
    )
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    websites: Mapped[list[Website]] = relationship(
        back_populates="owner",
        foreign_keys="Website.owner_id",
        lazy="select",
    )
    notifications: Mapped[list[Notification]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    activities: Mapped[list[UserActivity]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    admin_actions: Mapped[list[AdminAction]] = relationship(
        back_populates="admin",
        foreign_keys="AdminAction.admin_user_id",
    )
    github_installations: Mapped[list[GithubInstallation]] = relationship(
        back_populates="user"
    )

    @validates("email")
    def _normalize_email(self, _key: str, value: str) -> str:
        return (value or "").strip().lower()

    @property
    def is_active(self) -> bool:
        return self.status == UserStatus.ACTIVE

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    def get_id(self) -> str:
        return self.id

    @property
    def initials(self) -> str:
        parts = [part for part in (self.display_name or self.email).split() if part]
        if not parts:
            return "?"
        if len(parts) == 1:
            return parts[0][:2].upper()
        return (parts[0][0] + parts[-1][0]).upper()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email} {self.status.value}>"


class UserIdentity(UUIDMixin, TimestampMixin, db.Model):
    __tablename__ = "user_identities"
    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_user_id", name="uq_identity_provider_subject"
        ),
        UniqueConstraint("user_id", "provider", name="uq_identity_user_provider"),
        Index("ix_identities_provider_email", "provider", "provider_email"),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[IdentityProvider] = mapped_column(
        sa_enum(IdentityProvider), nullable=False
    )
    provider_user_id: Mapped[str] = mapped_column(String(191), nullable=False)
    provider_email: Mapped[str | None] = mapped_column(String(320))
    provider_login: Mapped[str | None] = mapped_column(String(191))
    avatar_url: Mapped[str | None] = mapped_column(String(1024))
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    access_token_encrypted: Mapped[str | None] = mapped_column(Text)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(Text)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scopes: Mapped[str | None] = mapped_column(Text)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="identities")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<UserIdentity {self.provider.value}:{self.provider_user_id}>"


class UserSession(UUIDMixin, db.Model):
    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_active", "user_id", "revoked_at", "expires_at"),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_valid(self) -> bool:
        now = utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            now = now.replace(tzinfo=None)
        return self.revoked_at is None and expires > now


class UserQuota(BaseModel):
    __tablename__ = "user_quotas"
    __table_args__ = (
        CheckConstraint(
            "max_websites >= 1 AND max_websites <= 10",
            name="user_quotas_max_websites_range",
        ),
        CheckConstraint("ram_limit_mb > 0", name="user_quotas_ram_positive"),
        CheckConstraint("storage_limit_mb > 0", name="user_quotas_storage_positive"),
        CheckConstraint("cpu_limit > 0", name="user_quotas_cpu_positive"),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    plan_name: Mapped[str] = mapped_column(
        String(64), nullable=False, default="Free", index=True
    )
    max_websites: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    ram_limit_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=1024)
    storage_limit_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=5120)
    cpu_limit: Mapped[float] = mapped_column(db.Float, nullable=False, default=1.0)
    updated_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    user: Mapped[User] = relationship(back_populates="quota", foreign_keys=[user_id])
    updated_by: Mapped[User | None] = relationship(foreign_keys=[updated_by_id])

    def __repr__(self) -> str:  # pragma: no cover
        return f"<UserQuota user={self.user_id} sites={self.max_websites}>"
