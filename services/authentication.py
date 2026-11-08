"""Account resolution, account linking and server-side session tracking."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from flask import current_app, has_request_context, request, session
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import (
    IdentityProvider,
    User,
    UserIdentity,
    UserQuota,
    UserRole,
    UserSession,
    UserStatus,
)
from ..utils import client_ip, utcnow
from .audit import record_user_activity
from .oauth import OAuthProfile, save_identity_tokens

logger = logging.getLogger(__name__)

USER_SESSION_KEY = "user_session_id"
USER_SESSION_EXPIRES_KEY = "user_session_expires_at"


class AuthenticationFlowError(RuntimeError):
    """Safe, user-facing authentication failure."""


@dataclass
class AuthenticatedAccount:
    user: User
    identity: UserIdentity
    created_user: bool = False


def _active_or_raise(user: User) -> None:
    if user.status == UserStatus.SUSPENDED:
        raise AuthenticationFlowError(
            "This account is suspended. Contact the platform administrator."
        )
    if user.status == UserStatus.DELETED:
        raise AuthenticationFlowError("This account is no longer available.")


def _get_identity(profile: OAuthProfile) -> UserIdentity | None:
    return UserIdentity.query.filter_by(
        provider=profile.provider, provider_user_id=profile.subject
    ).one_or_none()


def authenticate_profile(
    profile: OAuthProfile, *, link_to: User | None = None
) -> AuthenticatedAccount:
    """Resolve a verified OAuth profile into a local account.

    If ``link_to`` is provided, the identity is linked to that existing account.
    Otherwise this is a login/registration flow.
    """
    if not profile.subject:
        raise AuthenticationFlowError(
            "The provider did not return a stable account identifier."
        )

    identity = _get_identity(profile)

    if link_to is not None:
        _active_or_raise(link_to)
        if identity is not None:
            if identity.user_id == link_to.id:
                save_identity_tokens(identity, profile)
                db.session.commit()
                return AuthenticatedAccount(link_to, identity)
            raise AuthenticationFlowError(
                "This provider account is already linked to a different ServerPilot account."
            )
        existing_provider = UserIdentity.query.filter_by(
            user_id=link_to.id, provider=profile.provider
        ).one_or_none()
        if existing_provider is not None:
            raise AuthenticationFlowError(
                f"A {profile.provider.value.title()} account is already linked. "
                "Disconnect it before adding another."
            )
        if not profile.email_verified:
            raise AuthenticationFlowError(
                "Only a provider-verified email address can be linked."
            )
        new_identity = UserIdentity(
            user_id=link_to.id,
            provider=profile.provider,
            provider_user_id=profile.subject,
            provider_email=profile.email,
            provider_login=profile.login,
            avatar_url=profile.avatar_url,
            email_verified=profile.email_verified,
            last_used_at=utcnow(),
        )
        save_identity_tokens(new_identity, profile)
        db.session.add(new_identity)
        try:
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise AuthenticationFlowError(
                "This provider account was just linked elsewhere. Try signing in again."
            ) from exc
        record_user_activity(
            user=link_to,
            action="identity_linked",
            resource_type="identity",
            resource_id=new_identity.id,
            description=f"Linked {profile.provider.value.title()} identity",
            commit=True,
        )
        return AuthenticatedAccount(link_to, new_identity)

    if identity is not None:
        user = identity.user
        _active_or_raise(user)
        save_identity_tokens(identity, profile)
        identity.last_used_at = utcnow()
        if not user.avatar_url and profile.avatar_url:
            user.avatar_url = profile.avatar_url
        user.last_login_at = utcnow()
        db.session.add(user)
        db.session.add(identity)
        db.session.commit()
        return AuthenticatedAccount(user, identity)

    if not profile.email or not profile.email_verified:
        raise AuthenticationFlowError(
            "A verified email address is required to create or access an account."
        )

    email = profile.email.strip().lower()
    existing_user = User.query.filter_by(email=email).one_or_none()
    if existing_user is not None:
        _active_or_raise(existing_user)
        linked = UserIdentity(
            user_id=existing_user.id,
            provider=profile.provider,
            provider_user_id=profile.subject,
            provider_email=email,
            provider_login=profile.login,
            avatar_url=profile.avatar_url,
            email_verified=True,
            last_used_at=utcnow(),
        )
        save_identity_tokens(linked, profile)
        db.session.add(linked)
        existing_user.last_login_at = utcnow()
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            retry = _get_identity(profile)
            if retry is None:
                raise AuthenticationFlowError(
                    "The account could not be linked. Try signing in again."
                )
            _active_or_raise(retry.user)
            return AuthenticatedAccount(retry.user, retry)
        record_user_activity(
            user=existing_user,
            action="identity_auto_linked",
            resource_type="identity",
            resource_id=linked.id,
            description=f"Verified {profile.provider.value.title()} email linked to existing account",
            commit=True,
        )
        return AuthenticatedAccount(existing_user, linked)

    user = User(
        email=email,
        display_name=(profile.display_name or email.split("@")[0])[:120],
        avatar_url=profile.avatar_url,
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
        last_login_at=utcnow(),
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(
        UserQuota(
            user_id=user.id,
            plan_name="Free",
            max_websites=current_app.config["DEFAULT_MAX_WEBSITES"],
            ram_limit_mb=current_app.config["DEFAULT_RAM_LIMIT_MB"],
            storage_limit_mb=current_app.config["DEFAULT_STORAGE_LIMIT_MB"],
            cpu_limit=1.0,
        )
    )
    new_identity = UserIdentity(
        user_id=user.id,
        provider=profile.provider,
        provider_user_id=profile.subject,
        provider_email=email,
        provider_login=profile.login,
        avatar_url=profile.avatar_url,
        email_verified=True,
        last_used_at=utcnow(),
    )
    save_identity_tokens(new_identity, profile)
    db.session.add(new_identity)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        retry = _get_identity(profile)
        if retry is not None:
            _active_or_raise(retry.user)
            return AuthenticatedAccount(retry.user, retry)
        raise AuthenticationFlowError(
            "The account could not be created because it was created concurrently. "
            "Try signing in again."
        ) from exc
    record_user_activity(
        user=user,
        action="account_created",
        description=f"Account created via {profile.provider.value.title()}",
        commit=True,
    )
    return AuthenticatedAccount(user, new_identity, created_user=True)


def establish_user_session(user: User) -> UserSession:
    """Rotate the Flask session and create a tracked server-side session."""
    lifetime = current_app.config["PERMANENT_SESSION_LIFETIME"]
    now = utcnow()
    session.clear()
    session.permanent = True
    ip = client_ip() if has_request_context() else None
    ua = (request.user_agent.string or "")[:512] if has_request_context() else None
    row = UserSession(
        user_id=user.id,
        ip_address=ip,
        user_agent=ua,
        created_at=now,
        last_seen_at=now,
        expires_at=now + lifetime,
    )
    db.session.add(row)
    db.session.commit()
    session[USER_SESSION_KEY] = row.id
    session[USER_SESSION_EXPIRES_KEY] = row.expires_at.isoformat()
    session["authenticated_at"] = now.isoformat()
    return row


def current_user_session(user: User) -> UserSession | None:
    sid = session.get(USER_SESSION_KEY)
    if not sid:
        return None
    row = db.session.get(UserSession, sid)
    if row is None or row.user_id != user.id or not row.is_valid:
        return None
    return row


def touch_user_session(user: User, row: UserSession) -> None:
    now = utcnow()
    last = row.last_seen_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=now.tzinfo)
    if (now - last).total_seconds() >= 300:
        row.last_seen_at = now
        db.session.commit()


def revoke_user_session() -> None:
    sid = session.get(USER_SESSION_KEY)
    if sid:
        row = db.session.get(UserSession, sid)
        if row is not None and row.revoked_at is None:
            row.revoked_at = utcnow()
            db.session.commit()
    session.pop(USER_SESSION_KEY, None)
    session.pop(USER_SESSION_EXPIRES_KEY, None)


def revoke_all_sessions(user: User) -> int:
    count = UserSession.query.filter_by(user_id=user.id, revoked_at=None).update(
        {"revoked_at": utcnow()}, synchronize_session=False
    )
    db.session.commit()
    return count


def disconnect_identity(user: User, provider: IdentityProvider) -> None:
    identity = UserIdentity.query.filter_by(
        user_id=user.id, provider=provider
    ).one_or_none()
    if identity is None:
        raise AuthenticationFlowError("That provider is not connected.")
    total = UserIdentity.query.filter_by(user_id=user.id).count()
    if total <= 1:
        raise AuthenticationFlowError(
            "You cannot disconnect your only sign-in method. Connect another "
            "provider first."
        )
    from .oauth import revoke_identity_tokens

    revoke_identity_tokens(identity)
    db.session.delete(identity)
    db.session.commit()
    record_user_activity(
        user=user,
        action="identity_disconnected",
        resource_type="identity",
        resource_id=identity.id,
        description=f"Disconnected {provider.value.title()} identity",
        commit=True,
    )


def session_lifetime_seconds() -> int:
    return int(current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds())


def new_session_expiry():
    return utcnow() + timedelta(seconds=session_lifetime_seconds())
