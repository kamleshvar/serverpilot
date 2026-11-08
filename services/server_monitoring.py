"""Server liveness checks and administrator notifications."""

from __future__ import annotations

from datetime import timedelta

from flask import current_app

from ..extensions import db
from ..models import (
    AgentStatus,
    Server,
    ServerConnectionStatus,
    ServerStatus,
)
from ..utils import as_utc, utcnow
from .audit import notify_admins


def refresh_server_health(*, commit: bool = True) -> int:
    """Mark stale agents/servers offline and alert administrators once per outage."""
    cutoff = utcnow() - timedelta(
        seconds=int(current_app.config.get("AGENT_OFFLINE_AFTER_SECONDS", 120))
    )
    changed = 0
    servers = Server.query.filter(Server.deleted_at.is_(None)).all()
    for server in servers:
        if (
            server.status == ServerStatus.DISABLED
            or server.approval_status.value == "rejected"
        ):
            continue
        last = as_utc(server.last_heartbeat_at)
        stale = last is None or last < cutoff
        if not stale:
            continue
        was_online = server.status == ServerStatus.ONLINE
        if was_online:
            server.status = ServerStatus.OFFLINE
            server.connection_status = ServerConnectionStatus.OFFLINE
            server.last_error = (
                "The agent heartbeat stopped. The server is marked offline until "
                "it reconnects."
            )
            changed += 1
            for agent in server.agents:
                if agent.status == AgentStatus.ACTIVE:
                    agent.status = AgentStatus.OFFLINE
            notify_admins(
                category="server_offline",
                title=f"Server offline: {server.name}",
                body=(
                    f"No agent heartbeat has been received from {server.hostname} "
                    f"within {current_app.config.get('AGENT_OFFLINE_AFTER_SECONDS', 120)} seconds."
                ),
                dedupe_key=f"server-offline:{server.id}",
                link=f"/techorigin/servers/{server.id}",
                details={"server_id": server.id, "hostname": server.hostname},
            )
    if changed and commit:
        db.session.commit()
    return changed
