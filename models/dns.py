"""Cloudflare-backed DNS records and domain health state."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import BaseModel, sa_enum
from .enums import DnsRecordType, DnsStatus

if TYPE_CHECKING:
    from .infrastructure import Domain
    from .website import Website


class DnsRecord(BaseModel):
    __tablename__ = "dns_records"
    __table_args__ = (
        UniqueConstraint(
            "domain_id", "name", "record_type", name="uq_dns_domain_name_type"
        ),
        Index("ix_dns_records_website", "website_id"),
        Index("ix_dns_records_status_checked", "status", "last_checked_at"),
    )

    domain_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    website_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("websites.id", ondelete="SET NULL"), index=True
    )
    record_type: Mapped[DnsRecordType] = mapped_column(
        sa_enum(DnsRecordType), nullable=False
    )
    name: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    proxied: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cloudflare_record_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    managed_by_platform: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    status: Mapped[DnsStatus] = mapped_column(
        sa_enum(DnsStatus), nullable=False, default=DnsStatus.UNKNOWN
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    domain: Mapped[Domain] = relationship(back_populates="dns_records")
    website: Mapped[Website | None] = relationship(back_populates="dns_records")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DnsRecord {self.record_type.value} {self.name}>"
