"""Independent administrator authentication and deployment authorization."""

from __future__ import annotations

import hmac
import logging
from datetime import datetime

from flask import current_app, session
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from ..extensions import db
from ..models import (
    AdminActionResult,
    IdentityProvider,
    User,
    UserIdentity,
    UserRole,
    UserStatus,
)
from ..utils import as_utc, utcnow
from .audit import record_admin_action
from .oauth import OAuthProfile, save_identity_tokens

logger = logging.getLogger(__name__)

ADMIN_ID_KEY = "admin_user_id"
ADMIN_AUTH_AT_KEY = "admin_authenticated_at"
ADMIN_DEPLOY_AUTH_AT_KEY = "admin_deployment_authorized_at"


class AdminAuthenticationError(RuntimeError):
    def __init__(self, message: str, *, reason: str = "invalid_credentials") -> None:
        super().__init__(message)
        self.reason = reason


def admin_password_configured() -> bool:
    return bool(
        current_app.config.get("ADMIN_PASSWORD_HASH")
        and current_app.config.get("ADMIN_EMAIL")
    )


def authenticate_admin(passcode: str) -> User:
    """Authenticate an administrator with the configured passcode only.

    The passcode is compared against ADMIN_PASSWORD_HASH; the hashed value is
    never stored in the database. The database administrator identity itself is
    provisioned out-of-band via 'flask --app wsgi create-admin'.
    """
    cfg_hash = current_app.config.get("ADMIN_PASSWORD_HASH") or ""
    if not (cfg_hash and current_app.config.get("ADMIN_EMAIL")):
        raise AdminAuthenticationError(
            "Administrator authentication is not configured on this server. "
            "Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH.",
            reason="config_missing",
        )

    try:
        passcode_ok = check_password_hash(cfg_hash, passcode or "")
    except (ValueError, TypeError):
        passcode_ok = False

    admin = User.query.filter_by(
        email=(current_app.config["ADMIN_EMAIL"] or "").strip().lower(),
        role=UserRole.ADMIN,
    ).one_or_none()

    if not passcode_ok:
        raise AdminAuthenticationError(
            "Invalid administrator credentials.", reason="invalid_credentials"
        )
    if admin is None:
        raise AdminAuthenticationError(
            "The administrator identity is not provisioned in the database. "
            "Run 'flask --app wsgi create-admin' with the configured ADMIN_EMAIL.",
            reason="admin_not_provisioned",
        )
    if admin.status != UserStatus.ACTIVE:
        raise AdminAuthenticationError(
            "The administrator account is not active.", reason="admin_inactive"
        )
    return admin


def establish_admin_session(admin: User) -> None:
    now = utcnow()
    session.clear()
    session[ADMIN_ID_KEY] = admin.id
    session[ADMIN_AUTH_AT_KEY] = now.isoformat()
    session.permanent = True


def clear_admin_session() -> None:
    session.pop(ADMIN_ID_KEY, None)
    session.pop(ADMIN_AUTH_AT_KEY, None)
    session.pop(ADMIN_DEPLOY_AUTH_AT_KEY, None)


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return as_utc(datetime.fromisoformat(raw))
    except (ValueError, TypeError):
        return None


def admin_session_user() -> User | None:
    admin_id = session.get(ADMIN_ID_KEY)
    authenticated_at = _parse_ts(session.get(ADMIN_AUTH_AT_KEY))
    if not admin_id or authenticated_at is None:
        return None
    lifetime = current_app.config["ADMIN_SESSION_LIFETIME"]
    if utcnow() - authenticated_at > lifetime:
        clear_admin_session()
        return None
    admin = db.session.get(User, admin_id)
    if (
        admin is None
        or admin.role != UserRole.ADMIN
        or admin.status != UserStatus.ACTIVE
    ):
        clear_admin_session()
        return None
    return admin


def admin_session_expires_at() -> datetime | None:
    authenticated_at = _parse_ts(session.get(ADMIN_AUTH_AT_KEY))
    if authenticated_at is None:
        return None
    return authenticated_at + current_app.config["ADMIN_SESSION_LIFETIME"]


def admin_deployment_auth_required() -> bool:
    return bool(current_app.config.get("ADMIN_DEPLOYMENT_AUTH_REQUIRED", True))


def admin_deployment_authorized() -> bool:
    if not admin_deployment_auth_required():
        return True
    authorized_at = _parse_ts(session.get(ADMIN_DEPLOY_AUTH_AT_KEY))
    if authorized_at is None:
        return False
    lifetime = current_app.config["ADMIN_DEPLOYMENT_AUTH_LIFETIME"]
    if utcnow() - authorized_at > lifetime:
        session.pop(ADMIN_DEPLOY_AUTH_AT_KEY, None)
        return False
    return True


def admin_deployment_expires_at() -> datetime | None:
    authorized_at = _parse_ts(session.get(ADMIN_DEPLOY_AUTH_AT_KEY))
    if authorized_at is None:
        return None
    return authorized_at + current_app.config["ADMIN_DEPLOYMENT_AUTH_LIFETIME"]


def grant_admin_deployment_authorization(admin: User, profile: OAuthProfile) -> None:
    """Authorize a deployment session using a verified admin identity.

    Authorization is granted only when one of these holds:
      * the provider identity is already linked to the admin DB account;
      * the GitHub numeric ID matches ADMIN_GITHUB_ID;
      * a verified email matches ADMIN_EMAIL and verification is not waived.

    A provider identity linked to a different account is never silently stolen.
    """
    identity = UserIdentity.query.filter_by(
        provider=profile.provider, provider_user_id=profile.subject
    ).one_or_none()

    if identity is not None and identity.user_id != admin.id:
        raise AdminAuthenticationError(
            "This provider identity is linked to a different ServerPilot account. "
            "Resolve the conflict before using it for administrator deployment authorization.",
            reason="identity_conflict",
        )

    github_match = bool(
        profile.provider == IdentityProvider.GITHUB
        and current_app.config.get("ADMIN_GITHUB_ID")
        and hmac.compare_digest(
            profile.subject, str(current_app.config["ADMIN_GITHUB_ID"])
        )
    )
    email_match = bool(
        profile.email
        and profile.email_verified
        and current_app.config.get("ADMIN_EMAIL")
        and hmac.compare_digest(
            profile.email.strip().lower(),
            str(current_app.config["ADMIN_EMAIL"]).strip().lower(),
        )
    )
    already_linked = identity is not None and identity.user_id == admin.id

    if not (already_linked or github_match or email_match):
        raise AdminAuthenticationError(
            "This identity is not authorized for administrator deployments.",
            reason="identity_not_authorized",
        )

    if identity is None:
        existing_provider = UserIdentity.query.filter_by(
            user_id=admin.id, provider=profile.provider
        ).one_or_none()
        if existing_provider is not None:
            raise AdminAuthenticationError(
                "A different identity for this provider is already linked to the "
                "administrator account. Reconcile it in the database first.",
                reason="provider_already_linked",
            )
        if profile.email and not profile.email_verified and not github_match:
            raise AdminAuthenticationError(
                "The provider did not verify this email address.",
                reason="email_unverified",
            )
        identity = UserIdentity(
            user_id=admin.id,
            provider=profile.provider,
            provider_user_id=profile.subject,
            provider_email=profile.email,
            provider_login=profile.login,
            avatar_url=profile.avatar_url,
            email_verified=profile.email_verified,
            last_used_at=utcnow(),
        )
        save_identity_tokens(identity, profile)
        db.session.add(identity)
        try:
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise AdminAuthenticationError(
                "The identity was linked concurrently. Try again.",
                reason="identity_conflict",
            ) from exc
    else:
        save_identity_tokens(identity, profile)
        identity.last_used_at = utcnow()
        db.session.commit()

    session[ADMIN_DEPLOY_AUTH_AT_KEY] = utcnow().isoformat()
    record_admin_action(
        admin=admin,
        action="admin_deployment_auth",
        resource_type="admin_session",
        result=AdminActionResult.SUCCESS,
        details={"provider": profile.provider.value},
        commit=True,
    )


def audit_admin_login(
    admin: User | None, *, success: bool, reason: str | None = None
) -> None:
    if success and admin is not None:
        record_admin_action(
            admin=admin,
            action="admin_login",
            resource_type="admin_session",
            result=AdminActionResult.SUCCESS,
            commit=True,
        )
        return
    record_admin_action(
        admin=None,
        action="admin_login_failed",
        resource_type="admin_session",
        result=AdminActionResult.DENIED,
        details={"reason": reason or "invalid_credentials"},
        commit=True,
    )
