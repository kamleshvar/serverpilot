"""GitHub App installations and webhook delivery idempotency."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import BaseModel, sa_enum
from .enums import GithubInstallationStatus

if TYPE_CHECKING:
    from .user import User
    from .website import Website


class GithubInstallation(BaseModel):
    __tablename__ = "github_installations"
    __table_args__ = (
        Index("ix_github_installations_user_status", "user_id", "status"),
    )

    installation_id: Mapped[int] = mapped_column(
        BigInteger, nullable=False, unique=True, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    account_login: Mapped[str] = mapped_column(String(191), nullable=False)
    account_type: Mapped[str] = mapped_column(
        String(32), default="User", nullable=False
    )
    target_type: Mapped[str | None] = mapped_column(String(32))
    repository_selection: Mapped[str] = mapped_column(
        String(32), default="selected", nullable=False
    )
    status: Mapped[GithubInstallationStatus] = mapped_column(
        sa_enum(GithubInstallationStatus),
        nullable=False,
        default=GithubInstallationStatus.ACTIVE,
    )
    permissions: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    events: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User | None] = relationship(back_populates="github_installations")
    websites: Mapped[list[Website]] = relationship(
        back_populates="github_installation",
        foreign_keys="Website.github_installation_id",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<GithubInstallation {self.installation_id} {self.account_login}>"


class GithubWebhookEvent(BaseModel):
    __tablename__ = "github_webhook_events"
    __table_args__ = (
        UniqueConstraint("delivery_id", name="uq_github_webhook_delivery"),
        Index("ix_github_webhook_event_created", "event", "created_at"),
    )

    delivery_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str | None] = mapped_column(String(64))
    installation_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    signature_verified: Mapped[bool] = mapped_column(default=False, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<GithubWebhookEvent {self.event}:{self.delivery_id}>"
