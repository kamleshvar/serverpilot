"""User dashboard (role-scoped, ownership-filtered queries only)."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user

from ..decorators import active_user_required
from ..extensions import db
from ..models import Notification, Website, WebsiteStatus
from ..services.quota import quota_snapshot
from ..utils import utcnow

bp = Blueprint("dashboard", __name__)


@bp.get("/dashboard")
@active_user_required
def index():
    active_states = [
        status for status in WebsiteStatus if status != WebsiteStatus.DELETED
    ]
    websites = (
        Website.query.filter(
            Website.owner_id == current_user.id,
            Website.status.in_(active_states),
            Website.deleted_at.is_(None),
        )
        .order_by(Website.created_at.desc())
        .all()
    )
    running = sum(1 for site in websites if site.status == WebsiteStatus.RUNNING)
    quota = quota_snapshot(current_user)
    return render_template(
        "user/dashboard.html",
        websites=websites,
        running=running,
        quota=quota,
        max_websites=quota.max_websites,
    )


@bp.get("/notifications")
@active_user_required
def notifications():
    rows = (
        Notification.query.filter_by(user_id=current_user.id)
        .order_by(Notification.created_at.desc())
        .limit(200)
        .all()
    )
    unread = sum(1 for row in rows if not row.is_read)
    return render_template("user/notifications.html", notifications=rows, unread=unread)


@bp.post("/notifications/read")
@active_user_required
def mark_notifications_read():
    updated = Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).update(
        {"is_read": True, "read_at": utcnow()},
        synchronize_session=False,
    )
    db.session.commit()
    flash(f"Marked {updated} notification(s) as read.", "info")
    return redirect(url_for("dashboard.notifications"))
