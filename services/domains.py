"""Database-backed domain registry and backend domain permission checks."""

from __future__ import annotations

from flask import current_app

from ..config import ConfigurationError
from ..config import clean_domain as normalize_domain
from ..errors import PermissionDenied, ValidationError
from ..extensions import db
from ..models import Domain, DomainStatus, User
from ..utils import utcnow

ACTIVE_DOMAIN_STATUSES = {DomainStatus.ACTIVE, DomainStatus.PENDING}


def configured_domain_names() -> tuple[str, ...]:
    return tuple(current_app.config.get("DOMAINS", ()))


def user_allowed_domain_name() -> str:
    name = current_app.config.get("USER_ALLOWED_DOMAIN")
    if not name:
        raise ConfigurationError("USER_ALLOWED_DOMAIN is not configured")
    return str(name)


def seed_configured_domains(*, commit: bool = True) -> list[Domain]:
    """Idempotently synchronize the three env domains into the database.

    Existing administrative state (disabled/error) is preserved; only the
    user-allowed flag and configured set are reconciled.
    """
    names = list(configured_domain_names())
    if not names:
        raise ConfigurationError("No domains configured (DOMAIN_1..DOMAIN_3)")

    user_domain = user_allowed_domain_name()
    domains: list[Domain] = []
    for name in names:
        normalized = normalize_domain(name)
        domain = Domain.query.filter_by(name=normalized).one_or_none()
        if domain is None:
            domain = Domain(
                name=normalized,
                is_user_allowed=(normalized == user_domain),
                status=DomainStatus.ACTIVE,
            )
            db.session.add(domain)
        else:
            domain.is_user_allowed = normalized == user_domain
        domains.append(domain)

    unconfigured = Domain.query.filter(Domain.name.notin_(names)).all()
    for domain in unconfigured:
        domain.is_user_allowed = False

    if commit:
        db.session.commit()
    return domains


def all_managed_domains() -> list[Domain]:
    names = list(configured_domain_names())
    if not names:
        return []
    return Domain.query.filter(Domain.name.in_(names)).order_by(Domain.name.asc()).all()


def get_domain_by_name(name: str) -> Domain | None:
    normalized = normalize_domain(name)
    return Domain.query.filter_by(name=normalized).one_or_none()


def get_user_allowed_domain() -> Domain:
    domain = get_domain_by_name(user_allowed_domain_name())
    if domain is None or not domain.is_user_allowed:
        raise ConfigurationError(
            "The user domain is not seeded. Run 'flask seed-core' after migrations."
        )
    return domain


def ensure_domain_available(domain: Domain) -> None:
    if domain.status not in ACTIVE_DOMAIN_STATUSES:
        raise ValidationError(f"Domain {domain.name} is not active")
    if domain.name not in configured_domain_names():
        raise ValidationError("Domain is not configured on this platform")


def resolve_domain_for_user(user: User, domain_name: str) -> Domain:
    """Select a deployment domain with server-side authorization.

    Normal users are restricted to USER_ALLOWED_DOMAIN even if they submit a
    different domain in an API request. Administrators may use any configured,
    active domain.
    """
    try:
        domain = get_domain_by_name(domain_name)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if domain is None:
        raise ValidationError("The selected domain is not managed by ServerPilot")
    ensure_domain_available(domain)

    if user.is_admin:
        return domain

    allowed = user_allowed_domain_name()
    if domain.name != allowed or not domain.is_user_allowed:
        raise PermissionDenied(
            "Your account can only deploy under the domains assigned to your plan."
        )
    return domain


def resolve_domain_for_website_update(user: User, domain: Domain) -> None:
    if user.is_admin:
        ensure_domain_available(domain)
        return
    if domain.name != user_allowed_domain_name() or not domain.is_user_allowed:
        raise PermissionDenied("You cannot assign this domain")
    ensure_domain_available(domain)


def mark_dns_checked(domain: Domain, status, error: str | None = None) -> None:
    from ..models import DnsStatus

    domain.dns_status = status if isinstance(status, DnsStatus) else DnsStatus(status)
    domain.last_dns_check_at = utcnow()
    domain.dns_last_error = error
    db.session.add(domain)
