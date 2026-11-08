from __future__ import annotations

from datetime import timedelta

from flask import g

from serverpilot.extensions import db
from serverpilot.models import (
    Domain,
    Framework,
    User,
    UserQuota,
    UserRole,
    UserSession,
    UserStatus,
    Website,
    WebsiteStatus,
)
from serverpilot.utils import utcnow


def make_user(
    email: str,
    *,
    role: UserRole = UserRole.USER,
    status: UserStatus = UserStatus.ACTIVE,
    max_websites: int = 5,
    ram_limit_mb: int = 1024,
    storage_limit_mb: int = 5120,
    name: str | None = None,
) -> User:
    user = User(
        email=email,
        display_name=name or email.split("@")[0].title(),
        role=role,
        status=status,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(
        UserQuota(
            user_id=user.id,
            max_websites=max_websites,
            ram_limit_mb=ram_limit_mb,
            storage_limit_mb=storage_limit_mb,
        )
    )
    db.session.flush()
    return user


def sign_in(client, user: User) -> UserSession:
    now = utcnow()
    tracked = UserSession(
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=1),
    )
    db.session.add(tracked)
    db.session.commit()
    g.pop("_login_user", None)
    with client.session_transaction() as sess:
        sess["_user_id"] = user.id
        sess["_fresh"] = True
        sess.permanent = True
        sess["user_session_id"] = tracked.id
        sess["user_session_expires_at"] = tracked.expires_at.isoformat()
        sess["authenticated_at"] = now.isoformat()
    return tracked


def make_website(
    owner: User,
    *,
    subdomain: str = "project1",
    domain_name: str = "techorigin.online",
    status: WebsiteStatus = WebsiteStatus.PENDING,
    name: str | None = None,
    ram_limit_mb: int = 256,
    storage_limit_mb: int = 1024,
) -> Website:
    domain = Domain.query.filter_by(name=domain_name).one()
    website = Website(
        owner_id=owner.id,
        domain_id=domain.id,
        name=name or subdomain.replace("-", " ").title(),
        subdomain=subdomain,
        fqdn=f"{subdomain}.{domain.name}",
        status=status,
        framework=Framework.FLASK,
        ram_limit_mb=ram_limit_mb,
        storage_limit_mb=storage_limit_mb,
    )
    db.session.add(website)
    db.session.flush()
    return website
