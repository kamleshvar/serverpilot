"""The independent /techorigin administration console."""

from __future__ import annotations

import logging

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from ..decorators import admin_required
from ..errors import AppError, wants_json
from ..extensions import db, limiter
from ..forms import AdminLoginForm
from ..models import (
    AdminAction,
    AdminActionResult,
    AgentStatus,
    Backup,
    Container,
    ContainerStatus,
    Deployment,
    DeploymentStatus,
    Domain,
    Notification,
    NotificationAudience,
    Server,
    ServerAgent,
    ServerStatus,
    User,
    UserRole,
    UserStatus,
    Website,
    WebsiteStatus,
)
from ..services.admin_auth import (
    AdminAuthenticationError,
    admin_deployment_authorized,
    admin_deployment_expires_at,
    admin_session_expires_at,
    admin_session_user,
    audit_admin_login,
    authenticate_admin,
    clear_admin_session,
    establish_admin_session,
)
from ..services.audit import record_auth_attempt
from ..services.oauth import begin_authorize, provider_enabled, redirect_uri_for
from ..utils import utcnow

logger = logging.getLogger(__name__)

bp = Blueprint("admin", __name__, url_prefix="/techorigin")

PUBLIC_ADMIN_ENDPOINTS = {"admin.login", "admin.logout"}


@bp.context_processor
def inject_admin_context():
    endpoint = request.endpoint or ""
    if not endpoint.startswith(("admin.", "admin_servers.")):
        return {}
    return {
        "admin": getattr(g, "admin_user", None) or admin_session_user(),
        "admin_expires_at": admin_session_expires_at(),
        "admin_deployment_authorized": admin_deployment_authorized(),
    }


@bp.before_request
def require_admin_session():
    """Central guard for every admin route except login/logout.

    Individual routes additionally use @admin_required /
    @admin_deployment_required. This belt-and-braces check protects newly added
    routes from being accidentally left public.
    """
    if request.endpoint in PUBLIC_ADMIN_ENDPOINTS:
        return None
    admin = admin_session_user()
    if admin is None:
        if wants_json():
            from flask import jsonify

            return (
                jsonify(
                    {
                        "error": {
                            "code": "admin_authentication_required",
                            "message": "Administrator authentication is required.",
                        }
                    }
                ),
                401,
            )
        flash("Administrator authentication is required.", "warning")
        next_url = (
            request.full_path if request.method == "GET" else url_for("admin.dashboard")
        )
        return redirect(url_for("admin.login", next=next_url))
    g.admin_user = admin
    return None


def _safe_admin_next(raw: str | None) -> str:
    if raw and raw.startswith("/techorigin") and "\r" not in raw and "\n" not in raw:
        return raw
    return url_for("admin.dashboard")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["ADMIN_LOGIN_RATE_LIMIT"],
    methods=["POST"],
)
def login():
    if admin_session_user() is not None:
        return redirect(_safe_admin_next(request.args.get("next")))
    form = AdminLoginForm()
    config_ready = bool(
        current_app.config.get("ADMIN_PASSWORD_HASH")
        and current_app.config.get("ADMIN_EMAIL")
    )
    if form.validate_on_submit():
        try:
            admin = authenticate_admin(form.passcode.data or "")
        except AdminAuthenticationError as exc:
            record_auth_attempt(
                identifier="admin",
                provider="admin",
                success=False,
                reason=exc.reason,
            )
            audit_admin_login(None, success=False, reason=exc.reason)
            logger.warning(
                "Admin login failed reason=%s ip=%s", exc.reason, request.remote_addr
            )
            flash(
                str(exc)
                if exc.reason == "config_missing"
                else "Invalid administrator credentials.",
                "error",
            )
            return render_template(
                "admin/login.html",
                form=form,
                config_ready=config_ready,
                next_url=_safe_admin_next(request.args.get("next")),
            ), 200

        establish_admin_session(admin)
        record_auth_attempt(identifier=admin.email, provider="admin", success=True)
        audit_admin_login(admin, success=True)
        flash("Administrator session established.", "success")
        target = _safe_admin_next(request.form.get("next") or request.args.get("next"))
        return redirect(target)

    if request.method == "POST":
        record_auth_attempt(
            identifier="admin",
            provider="admin",
            success=False,
            reason="form_validation_failed",
        )
    return render_template(
        "admin/login.html",
        form=form,
        config_ready=config_ready,
        next_url=_safe_admin_next(request.args.get("next")),
    )


@bp.post("/logout")
def logout():
    admin = admin_session_user()
    if admin is not None:
        from ..models import AdminActionResult
        from ..services.audit import record_admin_action

        record_admin_action(
            admin=admin,
            action="admin_logout",
            resource_type="admin_session",
            result=AdminActionResult.SUCCESS,
            commit=True,
        )
    clear_admin_session()
    session.pop("oauth_mode", None)
    session.pop("oauth_next", None)
    session.pop("oauth_started_at", None)
    flash("Administrator session ended.", "info")
    return redirect(url_for("admin.login"))


@bp.get("/")
@admin_required
def dashboard():
    try:
        stats = _dashboard_stats()
    except SQLAlchemyError:
        db.session.rollback()
        logger.exception("Admin dashboard metrics query failed")
        stats = None
    recent_actions = (
        AdminAction.query.order_by(AdminAction.created_at.desc()).limit(8).all()
    )
    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent_actions=recent_actions,
        admin=g.admin_user,
        admin_expires_at=admin_session_expires_at(),
        deployment_authorized=admin_deployment_authorized(),
        deployment_expires_at=admin_deployment_expires_at(),
    )


@bp.get("/users")
@admin_required
def users():
    query_text = (request.args.get("q") or "").strip()
    status_filter = (request.args.get("status") or "").strip()
    query = User.query
    if query_text:
        pattern = f"%{query_text}%"
        query = query.filter(
            (User.email.ilike(pattern)) | (User.display_name.ilike(pattern))
        )
    if status_filter:
        try:
            query = query.filter(User.status == UserStatus(status_filter))
        except ValueError:
            status_filter = ""
    rows = query.order_by(User.created_at.desc()).limit(500).all()
    return render_template(
        "admin/users.html",
        users=rows,
        query_text=query_text,
        status_filter=status_filter,
        statuses=[status.value for status in UserStatus],
    )


@bp.post("/users/<user_id>/status")
@admin_required
def set_user_status(user_id: str):
    from ..services.audit import record_admin_action

    user = db.session.get(User, user_id)
    if user is None:
        flash("User not found.", "error")
        return redirect(url_for("admin.users"))
    requested = (request.form.get("status") or "").strip()
    try:
        new_status = UserStatus(requested)
    except ValueError:
        flash("Invalid user status.", "error")
        return redirect(url_for("admin.users"))
    if user.id == g.admin_user.id:
        flash("You cannot change your own administrator status here.", "warning")
        return redirect(url_for("admin.users"))
    if user.role == UserRole.ADMIN and new_status != UserStatus.ACTIVE:
        flash("Administrator accounts cannot be suspended from this page.", "warning")
        return redirect(url_for("admin.users"))
    previous = user.status
    user.status = new_status
    if new_status == UserStatus.DELETED:
        user.deleted_at = utcnow()
    db.session.commit()
    record_admin_action(
        admin=g.admin_user,
        action="user_status_changed",
        resource_type="user",
        resource_id=user.id,
        result=AdminActionResult.SUCCESS,
        details={"from": previous.value, "to": new_status.value},
        commit=True,
    )
    flash(f"{user.email} is now {new_status.value}.", "success")
    return redirect(url_for("admin.users"))


@bp.get("/sites")
@admin_required
def sites():
    status_filter = (request.args.get("status") or "").strip()
    query = Website.query
    if status_filter:
        try:
            query = query.filter(Website.status == WebsiteStatus(status_filter))
        except ValueError:
            status_filter = ""
    rows = query.order_by(Website.created_at.desc()).limit(500).all()
    return render_template(
        "admin/sites.html",
        websites=rows,
        status_filter=status_filter,
        statuses=[status.value for status in WebsiteStatus],
    )


@bp.post("/sites/<website_id>/force-stop")
@admin_required
def force_stop_site(website_id: str):
    from ..services.deployments import force_stop_website

    website = db.session.get(Website, website_id)
    if website is None:
        flash("Website not found.", "error")
        return redirect(url_for("admin.sites"))
    reason = (request.form.get("reason") or "").strip()
    try:
        force_stop_website(g.admin_user, website, reason)
    except AppError as exc:
        flash(exc.message, "error")
    else:
        flash(f"{website.fqdn} was force-stopped.", "success")
    return redirect(url_for("admin.sites"))


@bp.get("/domains")
@admin_required
def domains():
    rows = Domain.query.order_by(Domain.name).all()
    return render_template("admin/domains.html", domains=rows)


@bp.post("/domains/sync")
@admin_required
def sync_domains():
    from ..errors import AppError
    from ..services.cloudflare import sync_all_website_dns
    from ..services.cloudflare import sync_domains as sync_zones

    try:
        zones = sync_zones()
        websites = sync_all_website_dns()
    except AppError as exc:
        db.session.rollback()
        flash(exc.message, "error")
    else:
        flash(
            f"Synchronized {len(zones)} zones and {websites} website records.",
            "success",
        )
    return redirect(url_for("admin.domains"))


@bp.get("/backups")
@admin_required
def backups():
    rows = Backup.query.order_by(Backup.created_at.desc()).limit(500).all()
    return render_template("admin/backups.html", backups=rows)


@bp.get("/notifications")
@admin_required
def notifications():
    rows = (
        Notification.query.filter_by(audience=NotificationAudience.ADMIN)
        .order_by(Notification.created_at.desc())
        .limit(500)
        .all()
    )
    unread = sum(1 for row in rows if not row.is_read)
    return render_template(
        "admin/notifications.html", notifications=rows, unread=unread
    )


@bp.post("/notifications/read")
@admin_required
def mark_notifications_read():
    updated = Notification.query.filter_by(
        audience=NotificationAudience.ADMIN, is_read=False
    ).update(
        {"is_read": True, "read_at": utcnow()},
        synchronize_session=False,
    )
    db.session.commit()
    flash(f"Marked {updated} admin notification(s) as read.", "success")
    return redirect(url_for("admin.notifications"))


@bp.get("/deployment-auth")
@admin_required
def deployment_auth():
    return render_template(
        "admin/deployment_auth.html",
        admin=g.admin_user,
        required=current_app.config.get("ADMIN_DEPLOYMENT_AUTH_REQUIRED", True),
        authorized=admin_deployment_authorized(),
        expires_at=admin_deployment_expires_at(),
        google_available=provider_enabled("google"),
        github_available=provider_enabled("github"),
    )


@bp.get("/deployment-auth/start/<provider>")
@admin_required
@limiter.limit(lambda: current_app.config["OAUTH_LOGIN_RATE_LIMIT"])
def deployment_auth_start(provider: str):
    if provider not in {"google", "github"} or not provider_enabled(provider):
        flash(
            f"{provider.title()} deployment authorization is not configured.", "warning"
        )
        return redirect(url_for("admin.deployment_auth"))
    session["oauth_mode"] = "admin_deploy"
    session["oauth_next"] = url_for("admin.dashboard")
    session["oauth_started_at"] = utcnow().isoformat()
    try:
        return begin_authorize(provider, redirect_uri_for(provider))
    except Exception as exc:  # noqa: BLE001 - OAuth provider failures are opaque
        logger.warning("Could not start admin deployment OAuth: %s", type(exc).__name__)
        flash("The authentication provider could not be reached.", "error")
        return redirect(url_for("admin.deployment_auth"))


def _scalar(query, default=0):
    value = query.scalar()
    return value if value is not None else default


def _dashboard_stats() -> dict:
    total_users = _scalar(
        db.session.query(func.count(User.id)).filter(User.status != UserStatus.DELETED)
    )
    active_users = _scalar(
        db.session.query(func.count(User.id)).filter(User.status == UserStatus.ACTIVE)
    )
    suspended_users = _scalar(
        db.session.query(func.count(User.id)).filter(
            User.status == UserStatus.SUSPENDED
        )
    )
    total_websites = _scalar(
        db.session.query(func.count(Website.id)).filter(
            Website.status != WebsiteStatus.DELETED
        )
    )
    running_websites = _scalar(
        db.session.query(func.count(Website.id)).filter(
            Website.status == WebsiteStatus.RUNNING
        )
    )
    stopped_statuses = [
        WebsiteStatus.USER_STOPPED,
        WebsiteStatus.ADMIN_FORCED_STOP,
        WebsiteStatus.QUOTA_STOPPED,
        WebsiteStatus.FAILED,
    ]
    stopped_websites = _scalar(
        db.session.query(func.count(Website.id)).filter(
            Website.status.in_(stopped_statuses)
        )
    )
    failed_deployments = _scalar(
        db.session.query(func.count(Deployment.id)).filter(
            Deployment.status == DeploymentStatus.FAILED
        )
    )
    servers_total = _scalar(db.session.query(func.count(Server.id)))
    servers_online = _scalar(
        db.session.query(func.count(Server.id)).filter(
            Server.status == ServerStatus.ONLINE
        )
    )
    agents_online = _scalar(
        db.session.query(func.count(ServerAgent.id)).filter(
            ServerAgent.status == AgentStatus.ACTIVE
        )
    )
    running_containers = _scalar(
        db.session.query(func.count(Container.id)).filter(
            Container.status == ContainerStatus.RUNNING
        )
    )
    measured_ram = _scalar(
        db.session.query(func.coalesce(func.sum(Container.last_ram_mb), 0.0)).filter(
            Container.status == ContainerStatus.RUNNING
        ),
        0.0,
    )
    measured_storage = _scalar(
        db.session.query(
            func.coalesce(func.sum(Container.last_storage_mb), 0.0)
        ).filter(Container.status == ContainerStatus.RUNNING),
        0.0,
    )
    total_ram_capacity = _scalar(
        db.session.query(func.coalesce(func.sum(Server.total_ram_mb), 0))
    )
    total_storage_capacity = _scalar(
        db.session.query(func.coalesce(func.sum(Server.total_storage_mb), 0))
    )
    domain_rows = Domain.query.order_by(Domain.name).all()
    healthy_domains = sum(
        1 for domain in domain_rows if domain.dns_status.value in {"valid", "unknown"}
    )
    return {
        "total_users": total_users,
        "active_users": active_users,
        "suspended_users": suspended_users,
        "total_websites": total_websites,
        "running_websites": running_websites,
        "stopped_websites": stopped_websites,
        "failed_deployments": failed_deployments,
        "servers_total": servers_total,
        "servers_online": servers_online,
        "agents_online": agents_online,
        "running_containers": running_containers,
        "measured_ram_mb": round(float(measured_ram or 0), 1),
        "measured_storage_mb": round(float(measured_storage or 0), 1),
        "total_ram_capacity_mb": int(total_ram_capacity or 0),
        "total_storage_capacity_mb": int(total_storage_capacity or 0),
        "domains": domain_rows,
        "healthy_domains": healthy_domains,
        "domain_count": len(domain_rows),
    }
