"""User OAuth login, account linking and server-side session enforcement."""

from __future__ import annotations

import logging
from datetime import datetime

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from ..errors import wants_json
from ..extensions import db, limiter
from ..models import IdentityProvider
from ..services.admin_auth import (
    AdminAuthenticationError,
    admin_session_user,
    grant_admin_deployment_authorization,
)
from ..services.audit import record_auth_attempt, record_user_activity
from ..services.authentication import (
    AuthenticationFlowError,
    authenticate_profile,
    current_user_session,
    disconnect_identity,
    establish_user_session,
    revoke_user_session,
    touch_user_session,
)
from ..services.oauth import (
    OAuthFlowError,
    begin_authorize,
    complete_authorize,
    provider_enabled,
    redirect_uri_for,
)
from ..utils import as_utc, is_safe_redirect, utcnow

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__)

_OAUTH_MODES = {"login", "link", "admin_deploy"}
_OAUTH_MAX_AGE_SECONDS = 600


def _provider_from_path(provider: str) -> IdentityProvider:
    try:
        return IdentityProvider(provider)
    except ValueError:
        return None  # type: ignore[return-value]


def _safe_user_next(raw: str | None) -> str:
    if raw and is_safe_redirect(raw):
        return raw
    return "/dashboard"


def _safe_admin_next(raw: str | None) -> str:
    if raw and is_safe_redirect(raw) and raw.startswith("/techorigin"):
        return raw
    return url_for("admin.dashboard")


def _oauth_state() -> tuple[str | None, str | None, str | None]:
    mode = session.pop("oauth_mode", None)
    next_url = session.pop("oauth_next", None)
    started_raw = session.pop("oauth_started_at", None)
    return mode, next_url, started_raw


def _state_is_fresh(raw: str | None) -> bool:
    if not raw:
        return False
    try:
        started = as_utc(datetime.fromisoformat(raw))
    except (ValueError, TypeError):
        return False
    if started is None:
        return False
    return (utcnow() - started).total_seconds() <= _OAUTH_MAX_AGE_SECONDS


@bp.get("/auth/login")
def login():
    if current_user.is_authenticated:
        return redirect(_safe_user_next(request.args.get("next")))
    return render_template(
        "auth/login.html",
        next_url=_safe_user_next(request.args.get("next")),
    )


@bp.get("/auth/<provider>")
@limiter.limit(lambda: current_app.config["OAUTH_LOGIN_RATE_LIMIT"])
def oauth_start(provider: str):
    provider_enum = _provider_from_path(provider)
    if provider_enum is None:
        return render_template(
            "errors/error.html",
            status_code=404,
            error_code="not_found",
            message="Authentication provider not found.",
        ), 404
    if not provider_enabled(provider_enum):
        flash(
            f"{provider.title()} sign-in is not configured on this platform yet.",
            "warning",
        )
        return redirect(url_for("auth.login"))
    if current_user.is_authenticated:
        return redirect("/dashboard")

    next_url = _safe_user_next(request.args.get("next"))
    session["oauth_mode"] = "login"
    session["oauth_next"] = next_url
    session["oauth_started_at"] = utcnow().isoformat()
    try:
        return begin_authorize(provider, redirect_uri_for(provider))
    except OAuthFlowError as exc:
        flash(str(exc), "error")
        return redirect(url_for("auth.login"))


@bp.get("/settings/connections/link/<provider>")
@login_required
@limiter.limit(lambda: current_app.config["OAUTH_LOGIN_RATE_LIMIT"])
def link_profile(provider: str):
    provider_enum = _provider_from_path(provider)
    if provider_enum is None:
        return redirect("/settings/connections")
    if not provider_enabled(provider_enum):
        flash(f"{provider.title()} authentication is not configured.", "warning")
        return redirect("/settings/connections")
    session["oauth_mode"] = "link"
    session["oauth_next"] = "/settings/connections"
    session["oauth_started_at"] = utcnow().isoformat()
    try:
        return begin_authorize(provider, redirect_uri_for(provider))
    except OAuthFlowError as exc:
        flash(str(exc), "error")
        return redirect("/settings/connections")


@bp.get("/auth/<provider>/callback")
@limiter.limit(lambda: current_app.config["OAUTH_LOGIN_RATE_LIMIT"])
def oauth_callback(provider: str):
    provider_enum = _provider_from_path(provider)
    if provider_enum is None:
        return redirect(url_for("auth.login"))

    mode, next_url, started_raw = _oauth_state()
    if mode not in _OAUTH_MODES or not _state_is_fresh(started_raw):
        record_auth_attempt(
            identifier=None,
            provider=provider,
            success=False,
            reason="invalid_or_expired_oauth_state",
        )
        flash(
            "The sign-in attempt expired or was not started from this browser. "
            "Please start again.",
            "error",
        )
        return redirect(url_for("auth.login"))

    if mode == "admin_deploy":
        admin = admin_session_user()
        if admin is None:
            flash(
                "Administrator session expired. Sign in to administration again.",
                "warning",
            )
            return redirect(url_for("admin.login"))
        try:
            profile = complete_authorize(provider, redirect_uri_for(provider))
            grant_admin_deployment_authorization(admin, profile)
        except (
            OAuthFlowError,
            AuthenticationFlowError,
            AdminAuthenticationError,
        ) as exc:
            logger.warning(
                "Admin deployment authorization failed provider=%s reason=%s",
                provider,
                type(exc).__name__,
            )
            flash(str(exc), "error")
            return redirect(url_for("admin.deployment_auth"))
        flash("Deployment authorization confirmed.", "success")
        return redirect(_safe_admin_next(next_url))

    if mode == "link":
        if not current_user.is_authenticated:
            flash("Sign in before linking an account.", "warning")
            return redirect(url_for("auth.login"))
        try:
            profile = complete_authorize(provider, redirect_uri_for(provider))
            authenticate_profile(profile, link_to=current_user)
        except (OAuthFlowError, AuthenticationFlowError) as exc:
            flash(str(exc), "error")
            return redirect("/settings/connections")
        flash(f"{provider.title()} account linked successfully.", "success")
        return redirect(_safe_user_next(next_url))

    # Regular login / registration
    try:
        profile = complete_authorize(provider, redirect_uri_for(provider))
        account = authenticate_profile(profile)
    except OAuthFlowError as exc:
        record_auth_attempt(
            identifier=None,
            provider=provider,
            success=False,
            reason="oauth_flow_error",
        )
        flash(str(exc), "error")
        return redirect(url_for("auth.login"))
    except AuthenticationFlowError as exc:
        record_auth_attempt(
            identifier=None,
            provider=provider,
            success=False,
            reason="account_not_authorized",
        )
        flash(str(exc), "error")
        return redirect(url_for("auth.login"))

    establish_user_session(account.user)
    login_user(account.user, remember=False, force=False)
    account.user.last_login_at = utcnow()
    db.session.commit()
    record_auth_attempt(
        identifier=account.user.email,
        provider=provider,
        success=True,
        commit=True,
    )
    record_user_activity(
        user=account.user,
        action="login",
        description=f"Signed in with {provider.title()}",
        resource_type="session",
        commit=True,
    )
    if account.created_user:
        flash("Welcome to ServerPilot. Your Free plan is ready.", "success")
    else:
        flash("Signed in successfully.", "success")
    return redirect(_safe_user_next(next_url))


@bp.post("/auth/logout")
@login_required
def logout():
    user = current_user
    record_user_activity(
        user=user,
        action="logout",
        description="Signed out",
        resource_type="session",
        commit=False,
    )
    revoke_user_session()
    logout_user()
    session.clear()
    db.session.commit()
    flash("You have been signed out.", "info")
    return redirect(url_for("public.index"))


@bp.post("/settings/connections/<provider>/disconnect")
@login_required
def disconnect(provider: str):
    provider_enum = _provider_from_path(provider)
    if provider_enum is None:
        flash("Unknown identity provider.", "error")
        return redirect("/settings/connections")
    try:
        disconnect_identity(current_user, provider_enum)
    except AuthenticationFlowError as exc:
        flash(str(exc), "error")
        return redirect("/settings/connections")
    flash(f"{provider.title()} account disconnected.", "success")
    return redirect("/settings/connections")


@bp.before_app_request
def enforce_tracked_session():
    endpoint = request.endpoint or ""
    if endpoint.startswith("static") or endpoint == "public.healthz":
        return None
    if not current_user.is_authenticated:
        return None
    row = current_user_session(current_user)
    if row is None:
        logout_user()
        session.clear()
        if wants_json():
            error = {
                "code": "session_expired",
                "message": "Your session has expired. Sign in again.",
            }
            return jsonify({"error": error}), 401
        flash("Your session expired. Sign in again.", "warning")
        return redirect(url_for("auth.login", next=request.full_path))
    touch_user_session(current_user, row)
    return None
