"""Short-lived, single-use agent enrollment tokens."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from flask import current_app

from ..errors import AuthenticationRequired, ConflictError, NotFoundError
from ..extensions import db
from ..models import (
    AgentEnrollment,
    Server,
    ServerApprovalStatus,
)
from ..utils import utcnow


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_enrollment_token(server: Server, *, created_by_id: str | None) -> str:
    if server.deleted_at is not None:
        raise NotFoundError("Server not found.")
    if server.approval_status == ServerApprovalStatus.REJECTED:
        raise ConflictError("Rejected servers cannot enroll an agent.")
    now = utcnow()
    AgentEnrollment.query.filter(
        AgentEnrollment.server_id == server.id,
        AgentEnrollment.used_at.is_(None),
        AgentEnrollment.expires_at > now,
    ).update({"expires_at": now}, synchronize_session=False)
    token = secrets.token_urlsafe(32)
    enrollment = AgentEnrollment(
        server_id=server.id,
        token_hash=_hash(token),
        created_by_id=created_by_id,
        expires_at=now
        + timedelta(
            seconds=int(current_app.config.get("AGENT_ENROLLMENT_TTL_SECONDS", 900))
        ),
    )
    db.session.add(enrollment)
    db.session.flush()
    return token


def consume_enrollment_token(token: str, agent_uid: str) -> AgentEnrollment:
    """Atomically consume an enrollment token; the caller commits the registration."""
    raw = (token or "").strip()
    if not raw or len(raw) > 256:
        raise AuthenticationRequired("Agent enrollment token is invalid.")
    now = utcnow()
    updated = AgentEnrollment.query.filter(
        AgentEnrollment.token_hash == _hash(raw),
        AgentEnrollment.used_at.is_(None),
        AgentEnrollment.expires_at > now,
    ).update(
        {"used_at": now, "used_by_agent_uid": agent_uid[:64]},
        synchronize_session=False,
    )
    if updated != 1:
        db.session.rollback()
        raise AuthenticationRequired(
            "Agent enrollment token is invalid, expired or already used."
        )
    enrollment = AgentEnrollment.query.filter_by(token_hash=_hash(raw)).one_or_none()
    if enrollment is None:
        db.session.rollback()
        raise AuthenticationRequired("Agent enrollment token is invalid.")
    return enrollment
