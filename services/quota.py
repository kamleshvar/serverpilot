"""Shared per-user quota enforcement.

Quotas apply to the account, never per website:

* website slots count every non-deleted website;
* storage is reserved by every non-deleted website because volumes persist
  while a website is stopped;
* RAM is reserved by websites that are running or actively building, so
  creating five websites is allowed while only the configured aggregate RAM
  budget may run at once.
"""

from __future__ import annotations

from dataclasses import dataclass

from flask import current_app
from sqlalchemy import func

from ..errors import QuotaExceededError, ValidationError
from ..extensions import db
from ..models import Container, ContainerStatus, User, UserQuota, Website, WebsiteStatus

WEBSITE_COUNTED_STATUSES = [
    status for status in WebsiteStatus if status != WebsiteStatus.DELETED
]
RAM_RESERVING_STATUSES = {WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}
STORAGE_RESERVING_STATUSES = WEBSITE_COUNTED_STATUSES


@dataclass(frozen=True)
class QuotaSnapshot:
    plan_name: str
    max_websites: int
    websites_used: int
    ram_limit_mb: int
    ram_reserved_mb: int
    ram_measured_mb: float
    storage_limit_mb: int
    storage_reserved_mb: int
    storage_measured_mb: float
    cpu_limit: float

    @property
    def websites_remaining(self) -> int:
        return max(0, self.max_websites - self.websites_used)

    @property
    def ram_remaining_mb(self) -> int:
        return max(0, self.ram_limit_mb - self.ram_reserved_mb)

    @property
    def storage_remaining_mb(self) -> int:
        return max(0, self.storage_limit_mb - self.storage_reserved_mb)

    @property
    def ram_percent(self) -> float:
        return (
            round(min(100.0, (self.ram_reserved_mb / self.ram_limit_mb) * 100), 1)
            if self.ram_limit_mb
            else 0.0
        )

    @property
    def storage_percent(self) -> float:
        return (
            round(
                min(100.0, (self.storage_reserved_mb / self.storage_limit_mb) * 100), 1
            )
            if self.storage_limit_mb
            else 0.0
        )

    @property
    def website_percent(self) -> float:
        return (
            round(min(100.0, (self.websites_used / self.max_websites) * 100), 1)
            if self.max_websites
            else 0.0
        )


def ensure_quota(user: User) -> UserQuota:
    quota = user.quota
    if quota is not None:
        return quota
    quota = UserQuota(
        user_id=user.id,
        plan_name="Free",
        max_websites=current_app.config["DEFAULT_MAX_WEBSITES"],
        ram_limit_mb=current_app.config["DEFAULT_RAM_LIMIT_MB"],
        storage_limit_mb=current_app.config["DEFAULT_STORAGE_LIMIT_MB"],
        cpu_limit=1.0,
    )
    db.session.add(quota)
    db.session.flush()
    user.quota = quota
    return quota


def quota_snapshot(user: User) -> QuotaSnapshot:
    quota = ensure_quota(user)
    base = Website.query.filter(
        Website.owner_id == user.id, Website.status.in_(WEBSITE_COUNTED_STATUSES)
    )
    websites_used = base.count()
    storage_reserved = (
        db.session.query(func.coalesce(func.sum(Website.storage_limit_mb), 0))
        .filter(
            Website.owner_id == user.id,
            Website.status.in_(STORAGE_RESERVING_STATUSES),
        )
        .scalar()
        or 0
    )
    ram_reserved = (
        db.session.query(func.coalesce(func.sum(Website.ram_limit_mb), 0))
        .filter(
            Website.owner_id == user.id,
            Website.status.in_(RAM_RESERVING_STATUSES),
        )
        .scalar()
        or 0
    )
    measured = (
        db.session.query(
            func.coalesce(func.sum(Container.last_ram_mb), 0.0),
            func.coalesce(func.sum(Container.last_storage_mb), 0.0),
        )
        .join(Website, Website.id == Container.website_id)
        .filter(
            Website.owner_id == user.id,
            Website.status != WebsiteStatus.DELETED,
            Container.status == ContainerStatus.RUNNING,
        )
        .one()
    )
    return QuotaSnapshot(
        plan_name=quota.plan_name,
        max_websites=quota.max_websites,
        websites_used=websites_used,
        ram_limit_mb=quota.ram_limit_mb,
        ram_reserved_mb=int(ram_reserved),
        ram_measured_mb=round(float(measured[0] or 0), 1),
        storage_limit_mb=quota.storage_limit_mb,
        storage_reserved_mb=int(storage_reserved),
        storage_measured_mb=round(float(measured[1] or 0), 1),
        cpu_limit=quota.cpu_limit,
    )


def _positive(value: float, label: str) -> None:
    if value is None or value <= 0:
        raise ValidationError(f"{label} must be greater than zero.")


def assert_can_create_website(
    user: User,
    *,
    ram_limit_mb: int,
    storage_limit_mb: int,
    cpu_limit: float,
) -> QuotaSnapshot:
    socket = quota_snapshot(user)
    _positive(ram_limit_mb, "Website RAM allocation")
    _positive(storage_limit_mb, "Website storage allocation")
    _positive(cpu_limit, "Website CPU allocation")

    if socket.websites_used >= socket.max_websites:
        raise QuotaExceededError(
            f"Your {socket.plan_name} plan allows {socket.max_websites} websites. "
            "Delete a website before creating another.",
            details={
                "limit": socket.max_websites,
                "used": socket.websites_used,
                "resource": "websites",
            },
        )
    if ram_limit_mb > socket.ram_limit_mb:
        raise QuotaExceededError(
            "A single website cannot reserve more RAM than your entire account quota.",
            details={
                "limit": socket.ram_limit_mb,
                "requested": ram_limit_mb,
                "resource": "ram",
            },
        )
    if socket.storage_reserved_mb + storage_limit_mb > socket.storage_limit_mb:
        raise QuotaExceededError(
            "This website's storage allocation exceeds the shared storage left on "
            "your account.",
            details={
                "limit": socket.storage_limit_mb,
                "reserved": socket.storage_reserved_mb,
                "requested": storage_limit_mb,
                "resource": "storage",
            },
        )
    return socket


def assert_website_ram_available(user: User, website: Website) -> QuotaSnapshot:
    """Check the shared RAM budget before a website starts or redeploys."""
    socket = quota_snapshot(user)
    others = (
        db.session.query(func.coalesce(func.sum(Website.ram_limit_mb), 0))
        .filter(
            Website.owner_id == user.id,
            Website.id != website.id,
            Website.status.in_({WebsiteStatus.RUNNING, WebsiteStatus.BUILDING}),
        )
        .scalar()
        or 0
    )
    if int(others) + website.ram_limit_mb > socket.ram_limit_mb:
        raise QuotaExceededError(
            "Starting this website would exceed your shared RAM quota. Stop another "
            "website or lower this website's RAM allocation.",
            details={
                "limit": socket.ram_limit_mb,
                "reserved_other": int(others),
                "requested": website.ram_limit_mb,
                "resource": "ram",
            },
        )
    if socket.ram_measured_mb > socket.ram_limit_mb:
        raise QuotaExceededError(
            "Your account is already using more RAM than its quota. Reduce running "
            "websites first.",
            details={
                "limit": socket.ram_limit_mb,
                "measured": socket.ram_measured_mb,
                "resource": "ram",
            },
        )
    return socket


def assert_storage_available_for_website(
    user: User, website: Website, *, storage_limit_mb: int
) -> QuotaSnapshot:
    socket = quota_snapshot(user)
    others = (
        db.session.query(func.coalesce(func.sum(Website.storage_limit_mb), 0))
        .filter(
            Website.owner_id == user.id,
            Website.id != website.id,
            Website.status.in_(STORAGE_RESERVING_STATUSES),
        )
        .scalar()
        or 0
    )
    _positive(storage_limit_mb, "Website storage allocation")
    if int(others) + storage_limit_mb > socket.storage_limit_mb:
        raise QuotaExceededError(
            "The requested storage exceeds your shared account storage quota.",
            details={
                "limit": socket.storage_limit_mb,
                "reserved_other": int(others),
                "requested": storage_limit_mb,
                "resource": "storage",
            },
        )
    return socket
