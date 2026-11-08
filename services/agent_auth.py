"""Agent registration, per-agent credentials and signed request verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
from datetime import timedelta
from typing import Any

from flask import current_app, request
from sqlalchemy.exc import IntegrityError

from ..errors import AuthenticationRequired, ConflictError, ValidationError
from ..extensions import db
from ..models import (
    AgentCredential,
    AgentInstallStatus,
    AgentNonce,
    AgentStatus,
    Server,
    ServerAgent,
    ServerApprovalStatus,
    ServerConnectionStatus,
    ServerStatus,
)
from ..utils import utcnow
from .agent_enrollment import consume_enrollment_token
from .encryption import get_encryption

logger = logging.getLogger(__name__)

MAX_CLOCK_SKEW_SECONDS = 300
NONCE_RETENTION_SECONDS = 900
_AGENT_UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


def _derive_secret(agent_uid: str, key_id: str) -> str:
    global_secret = str(current_app.config.get("AGENT_SIGNING_SECRET") or "")
    if not global_secret:
        raise ConflictError(
            "AGENT_SIGNING_SECRET is not configured; agent credentials cannot be issued."
        )
    digest = hmac.new(
        global_secret.encode("utf-8"),
        f"{agent_uid}:{key_id}".encode(),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _positive_int(value: Any, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0 or parsed > maximum:
        return default
    return parsed


def _positive_float(value: Any, *, default: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0 or parsed > maximum:
        return default
    return parsed


def _registration_payload(data: dict[str, Any]) -> dict[str, Any]:
    agent_uid = str(data.get("agent_uid") or "").strip()
    if not _AGENT_UID_RE.match(agent_uid):
        raise ValidationError("agent_uid is missing or invalid.")
    hostname = str(data.get("hostname") or "").strip().lower().rstrip(".")
    if not _HOSTNAME_RE.match(hostname):
        raise ValidationError("hostname is missing or invalid.")
    name = str(data.get("name") or hostname).strip()[:120] or hostname[:120]
    version = str(data.get("version") or "").strip()[:32] or None
    capabilities = data.get("capabilities")
    if capabilities is not None and not isinstance(capabilities, dict):
        raise ValidationError("capabilities must be an object.")
    return {
        "agent_uid": agent_uid,
        "hostname": hostname,
        "name": name,
        "version": version,
        "capabilities": capabilities or {},
    }


def register_agent(data: dict[str, Any]) -> dict[str, Any]:
    """Register an agent using a single-use enrollment token or the legacy bootstrap token."""
    payload = _registration_payload(data)
    enrollment_token = request.headers.get("X-Enrollment-Token", "")
    enrollment = None
    if enrollment_token:
        enrollment = consume_enrollment_token(enrollment_token, payload["agent_uid"])
        server = db.session.get(Server, enrollment.server_id)
        if server is None or server.deleted_at is not None:
            raise AuthenticationRequired("The enrollment server no longer exists.")
        if server.approval_status == ServerApprovalStatus.REJECTED:
            raise AuthenticationRequired(
                "This server has been rejected by an administrator."
            )
    else:
        configured = str(current_app.config.get("AGENT_BOOTSTRAP_TOKEN") or "")
        supplied = request.headers.get("X-Bootstrap-Token", "")
        if not configured:
            raise AuthenticationRequired("Agent bootstrap is disabled.")
        if not hmac.compare_digest(configured, supplied):
            logger.warning("Agent registration rejected: invalid bootstrap token")
            raise AuthenticationRequired("Invalid agent bootstrap token.")
        server = Server.query.filter_by(
            hostname=payload["hostname"], deleted_at=None
        ).one_or_none()
        if (
            server is not None
            and server.approval_status == ServerApprovalStatus.REJECTED
        ):
            raise AuthenticationRequired(
                "This server has been rejected by an administrator."
            )

    capabilities = payload["capabilities"]
    if server is None:
        total_ram = _positive_int(
            capabilities.get("total_ram_mb"), default=2048, maximum=4_194_304
        )
        total_storage = _positive_int(
            capabilities.get("total_storage_mb"), default=40960, maximum=1_048_576_000
        )
        total_cpu = _positive_float(
            capabilities.get("total_cpu_cores"), default=2.0, maximum=4096.0
        )
        server = Server(
            name=payload["name"],
            hostname=payload["hostname"],
            status=ServerStatus.ONLINE,
            approval_status=ServerApprovalStatus.PENDING,
            connection_status=ServerConnectionStatus.CONNECTED,
            total_ram_mb=total_ram,
            total_storage_mb=total_storage,
            total_cpu_cores=total_cpu,
            is_default=Server.query.filter(Server.deleted_at.is_(None)).count() == 0,
        )
        db.session.add(server)
        db.session.flush()
        logger.info("Registered new agent server %s", server.hostname)
    else:
        server.status = ServerStatus.ONLINE
        server.connection_status = ServerConnectionStatus.CONNECTED
        if not server.ip_address and enrollment is None:
            server.ip_address = payload["hostname"]

    agent = ServerAgent.query.filter_by(agent_uid=payload["agent_uid"]).one_or_none()
    if agent is not None and agent.server_id != server.id:
        raise ConflictError("That agent_uid is already registered to another server.")
    if agent is None:
        agent = ServerAgent(
            server_id=server.id,
            name=payload["name"],
            agent_uid=payload["agent_uid"],
            status=AgentStatus.ACTIVE,
            version=payload["version"],
            capabilities=capabilities,
            registered_at=utcnow(),
            last_seen_at=utcnow(),
        )
        db.session.add(agent)
        db.session.flush()
    else:
        agent.status = AgentStatus.ACTIVE
        agent.version = payload["version"]
        agent.capabilities = capabilities
        agent.last_seen_at = utcnow()
        agent.revoked_at = None
        agent.revoked_reason = None
        AgentCredential.query.filter_by(agent_id=agent.id).filter(
            AgentCredential.revoked_at.is_(None)
        ).update({"revoked_at": utcnow()}, synchronize_session=False)

    key_id = secrets.token_hex(12)
    secret = _derive_secret(agent.agent_uid, key_id)
    credential = AgentCredential(
        agent_id=agent.id,
        key_id=key_id,
        secret_encrypted=get_encryption().encrypt(secret) or "",
    )
    db.session.add(credential)
    server.agent_version = payload["version"]
    server.status = ServerStatus.ONLINE
    server.connection_status = ServerConnectionStatus.CONNECTED
    server.agent_install_status = AgentInstallStatus.INSTALLED
    server.last_heartbeat_at = utcnow()
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise ConflictError(
            "The server name or hostname is already registered to another agent."
        ) from exc

    logger.info(
        "Agent %s registered for server %s via %s",
        agent.agent_uid,
        server.hostname,
        "enrollment token" if enrollment is not None else "bootstrap token",
    )
    return {
        "agent": {
            "uid": agent.agent_uid,
            "name": agent.name,
            "server_id": server.id,
            "server_name": server.name,
        },
        "credential": {"key_id": key_id, "secret": secret},
        "heartbeat_interval": int(
            current_app.config.get("AGENT_HEARTBEAT_INTERVAL", 30)
        ),
        "poll_interval": int(current_app.config.get("AGENT_POLL_INTERVAL", 5)),
        "approval_status": server.approval_status.value,
    }


def _canonical_request(
    *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> str:
    digest = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{digest}"


def authenticate_agent() -> tuple[ServerAgent, Server]:
    """Validate an HMAC-signed agent request and return its agent/server."""
    key_id = request.headers.get("X-Agent-Key", "")
    timestamp = request.headers.get("X-Agent-Timestamp", "")
    nonce = request.headers.get("X-Agent-Nonce", "")
    signature = request.headers.get("X-Agent-Signature", "")
    if not all((key_id, timestamp, nonce, signature)):
        raise AuthenticationRequired("Agent authentication headers are missing.")
    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        raise AuthenticationRequired("Agent timestamp is invalid.") from exc
    now = int(time.time())
    if abs(now - sent_at) > MAX_CLOCK_SKEW_SECONDS:
        raise AuthenticationRequired(
            "Agent request timestamp is outside the allowed window."
        )
    if not (8 <= len(nonce) <= 128):
        raise AuthenticationRequired("Agent nonce is invalid.")

    credential = AgentCredential.query.filter_by(key_id=key_id).one_or_none()
    if credential is None or not credential.is_valid:
        raise AuthenticationRequired("Agent credential is invalid or revoked.")
    agent = credential.agent
    if agent.status not in {AgentStatus.ACTIVE, AgentStatus.OFFLINE}:
        raise AuthenticationRequired("The agent is not active.")

    try:
        secret = get_encryption().decrypt(credential.secret_encrypted)
    except Exception as exc:
        logger.error("Agent credential could not be decrypted key=%s", key_id)
        raise AuthenticationRequired("Agent credential cannot be verified.") from exc
    if not secret:
        raise AuthenticationRequired("Agent credential cannot be verified.")
    body = request.get_data(cache=True)
    canonical = _canonical_request(
        method=request.method,
        path=request.path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    expected = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning(
            "Agent request signature mismatch key=%s path=%s", key_id, request.path
        )
        raise AuthenticationRequired("Agent request signature is invalid.")

    now_dt = utcnow()
    AgentNonce.query.filter(AgentNonce.expires_at < now_dt).delete(
        synchronize_session=False
    )
    db.session.add(
        AgentNonce(
            key_id=key_id,
            nonce=nonce,
            seen_at=now_dt,
            expires_at=now_dt + timedelta(seconds=NONCE_RETENTION_SECONDS),
        )
    )
    try:
        credential.last_used_at = now_dt
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise AuthenticationRequired("Agent request nonce was already used.") from exc

    return agent, agent.server


def sign_for_agent(secret: str, payload: dict[str, Any]) -> str:
    body = _canonical_json(payload)
    return hmac.new(
        secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _canonical_json(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
