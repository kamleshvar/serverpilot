"""Small, dependency-light helpers shared across the codebase."""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

from flask import Request, request

RESERVED_SUBDOMAINS = {
    "www",
    "api",
    "app",
    "admin",
    "techorigin",
    "deploy",
    "status",
    "mail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "ssh",
    "ns1",
    "ns2",
    "dns",
    "cdn",
    "static",
    "assets",
    "support",
    "help",
    "billing",
    "docs",
    "blog",
    "panel",
    "dashboard",
    "control",
    "agent",
    "internal",
}

SUBDOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
WEBSITE_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def random_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def client_ip(req: Request | None = None) -> str:
    req = req or request
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return (req.remote_addr or "")[:45]


def is_safe_redirect(target: str | None) -> bool:
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme in {"http", "https"}
        and host_url.netloc == redirect_url.netloc
    )


def safe_next_url(fallback: str = "/dashboard") -> str:
    target = request.args.get("next") or request.form.get("next")
    return target if target and is_safe_redirect(target) else fallback


def validate_subdomain(value: str) -> str:
    normalized = (value or "").strip().lower()
    if not SUBDOMAIN_RE.match(normalized):
        raise ValueError(
            "Subdomain must be 1-63 lowercase letters, digits or hyphens, "
            "and must start and end with a letter or digit."
        )
    if normalized in RESERVED_SUBDOMAINS:
        raise ValueError("This subdomain is reserved")
    return normalized


def validate_env_key(value: str) -> str:
    normalized = (value or "").strip()
    if not ENV_KEY_RE.match(normalized):
        raise ValueError(
            "Environment variable names must start with A-Z and contain only "
            "A-Z, 0-9 and underscore (max 128 characters)."
        )
    return normalized


def mask_secret(value: str | None, visible: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:0] + "*" * max(4, len(value) - visible) + value[-visible:]


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def humanize_bytes(value: float | None) -> str:
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"


def pagination_params(default_per_page: int = 20, max_per_page: int = 100):
    page = request.args.get("page", 1, type=int) or 1
    per_page = request.args.get("per_page", default_per_page, type=int)
    per_page = max(1, min(per_page or default_per_page, max_per_page))
    return max(1, page), per_page
