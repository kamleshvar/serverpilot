"""Per-website environment variables. Values are encrypted at rest."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import BaseModel

if TYPE_CHECKING:
    from .user import User
    from .website import Website


class EnvironmentVariable(BaseModel):
    __tablename__ = "environment_variables"
    __table_args__ = (
        UniqueConstraint("website_id", "key", name="uq_env_website_key"),
        Index("ix_environment_variables_website", "website_id"),
    )

    website_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    value_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    website: Mapped[Website] = relationship(back_populates="environment_variables")
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id])
    updated_by: Mapped[User | None] = relationship(foreign_keys=[updated_by_id])

    def __repr__(self) -> str:  # pragma: no cover
        return f"<EnvironmentVariable {self.key}>"
