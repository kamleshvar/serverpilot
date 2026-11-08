"""Audit, activity, notification and authentication-attempt writers."""

from __future__ import annotations

from flask import Request, has_request_context, request
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import (
    AdminAction,
    AdminActionResult,
    AuthAttempt,
    Notification,
    NotificationAudience,
    Severity,
    User,
    UserActivity,
)
from ..utils import client_ip


def _request_context() -> tuple[str | None, str | None]:
    if not has_request_context():
        return None, None
    return client_ip(), (request.user_agent.string or "")[:512]


def record_user_activity(
    *,
    user: User | None,
    user_id: str | None = None,
    action: str,
    description: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    req: Request | None = None,
    commit: bool = False,
) -> UserActivity:
    ip, ua = _request_context()
    if req is not None:
        ip = client_ip(req)
        ua = (req.user_agent.string or "")[:512]
    activity = UserActivity(
        user_id=user.id if user else user_id,
        action=action[:64],
        description=(description or "")[:512] or None,
        resource_type=(resource_type or "")[:64] or None,
        resource_id=(resource_id or "")[:64] or None,
        ip_address=ip,
        user_agent=ua,
        details=details or {},
    )
    db.session.add(activity)
    if commit:
        db.session.commit()
    return activity


def record_admin_action(
    *,
    admin: User | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    result: AdminActionResult = AdminActionResult.SUCCESS,
    details: dict | None = None,
    commit: bool = False,
) -> AdminAction:
    ip, ua = _request_context()
    if admin is not None and ip is None and has_request_context():
        ip = client_ip()
    entry = AdminAction(
        admin_user_id=admin.id if admin else None,
        admin_email=admin.email if admin else None,
        action=action[:64],
        resource_type=(resource_type or "")[:64] or None,
        resource_id=(resource_id or "")[:64] or None,
        result=result,
        ip_address=ip,
        user_agent=ua,
        details=details or {},
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry


def record_auth_attempt(
    *,
    identifier: str | None,
    provider: str,
    success: bool,
    reason: str | None = None,
    commit: bool = True,
) -> AuthAttempt:
    ip, ua = _request_context()
    attempt = AuthAttempt(
        identifier=(identifier or "")[:320] or None,
        provider=provider[:32],
        success=success,
        reason=(reason or "")[:255] or None,
        ip_address=ip,
        user_agent=ua,
    )
    db.session.add(attempt)
    if commit:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
    return attempt


def notify_user(
    user: User,
    *,
    category: str,
    title: str,
    body: str | None = None,
    severity: Severity = Severity.INFO,
    link: str | None = None,
    dedupe_key: str | None = None,
    details: dict | None = None,
    commit: bool = False,
) -> Notification:
    return _create_notification(
        audience=NotificationAudience.USER,
        user_id=user.id,
        category=category,
        title=title,
        body=body,
        severity=severity,
        link=link,
        dedupe_key=dedupe_key,
        details=details,
        commit=commit,
    )


def notify_admins(
    *,
    category: str,
    title: str,
    body: str | None = None,
    severity: Severity = Severity.WARNING,
    link: str | None = None,
    dedupe_key: str | None = None,
    details: dict | None = None,
    commit: bool = False,
) -> Notification:
    return _create_notification(
        audience=NotificationAudience.ADMIN,
        user_id=None,
        category=category,
        title=title,
        body=body,
        severity=severity,
        link=link,
        dedupe_key=dedupe_key,
        details=details,
        commit=commit,
    )


def _create_notification(
    *,
    audience: NotificationAudience,
    user_id: str | None,
    category: str,
    title: str,
    body: str | None,
    severity: Severity,
    link: str | None,
    dedupe_key: str | None,
    details: dict | None,
    commit: bool,
) -> Notification:
    if dedupe_key:
        existing = Notification.query.filter_by(dedupe_key=dedupe_key).one_or_none()
        if existing:
            existing.title = title[:255]
            existing.body = body
            existing.severity = severity
            existing.link = link
            existing.details = details or {}
            existing.is_read = False
            existing.read_at = None
            db.session.add(existing)
            if commit:
                db.session.commit()
            return existing
    notification = Notification(
        audience=audience,
        user_id=user_id,
        category=category[:64],
        title=title[:255],
        body=body,
        severity=severity,
        link=link,
        dedupe_key=dedupe_key,
        details=details or {},
    )
    db.session.add(notification)
    if commit:
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise
    return notification
