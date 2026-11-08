"""Authenticated agent API: registration, heartbeat, tasks and results."""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from ..errors import ConflictError, NotFoundError, ValidationError
from ..extensions import csrf, db
from ..models import (
    AgentStatus,
    AgentTask,
    Container,
    ContainerStatus,
    ResourceScope,
    ResourceUsage,
    Server,
    ServerAgent,
    ServerConnectionStatus,
    ServerResourceHistory,
    ServerStatus,
    TaskStatus,
)
from ..services.agent_auth import authenticate_agent, register_agent
from ..services.agent_tasks import (
    claim_next_task,
    task_payload_for_agent,
)
from ..services.deployments import append_logs, apply_task_result
from ..utils import utcnow

logger = logging.getLogger(__name__)

bp = Blueprint("agent_api", __name__, url_prefix="/api/v1/agent")
csrf.exempt(bp)


def _json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("A JSON object is required.")
    return data


def _signed_context() -> tuple[ServerAgent, Server]:
    agent, server = authenticate_agent()
    agent.status = AgentStatus.ACTIVE
    agent.last_seen_at = utcnow()
    server.last_heartbeat_at = utcnow()
    server.status = ServerStatus.ONLINE
    server.connection_status = ServerConnectionStatus.CONNECTED
    return agent, server


@bp.post("/register")
def register():
    return jsonify(register_agent(_json_body())), 201


@bp.post("/heartbeat")
def heartbeat():
    agent, server = _signed_context()
    data = _json_body()
    version = str(data.get("version") or "").strip()[:32] or None
    capabilities = data.get("capabilities")
    if capabilities is not None and not isinstance(capabilities, dict):
        raise ValidationError("capabilities must be an object.")
    if version:
        agent.version = version
        server.agent_version = version
    if capabilities is not None:
        agent.capabilities = capabilities
    metrics = data.get("metrics") or {}
    if not isinstance(metrics, dict):
        raise ValidationError("metrics must be an object.")

    def _number(name: str, default: float = 0.0) -> float:
        try:
            value = float(metrics.get(name, default))
        except (TypeError, ValueError):
            return default
        return max(0.0, value)

    cpu_percent = min(100.0, _number("cpu_percent"))
    ram_mb = _number("ram_mb")
    storage_mb = _number("storage_mb")
    db.session.add(
        ResourceUsage(
            scope=ResourceScope.SERVER,
            subject_id=server.id,
            server_id=server.id,
            cpu_percent=cpu_percent,
            ram_mb=ram_mb,
            storage_mb=storage_mb,
            container_count=max(0, int(_number("container_count"))),
            source="agent",
        )
    )
    db.session.add(
        ServerResourceHistory(
            server_id=server.id,
            cpu_usage=cpu_percent,
            ram_usage=min(100.0, (ram_mb / server.total_ram_mb) * 100)
            if server.total_ram_mb
            else 0.0,
            storage_usage=min(100.0, (storage_mb / server.total_storage_mb) * 100)
            if server.total_storage_mb
            else 0.0,
        )
    )

    containers = data.get("containers")
    if isinstance(containers, list):
        for item in containers[:500]:
            if not isinstance(item, dict):
                continue
            docker_id = str(item.get("docker_container_id") or "").strip()[:128]
            name = str(item.get("name") or "").strip()[:120]
            container = None
            if docker_id:
                container = Container.query.filter_by(
                    server_id=server.id, docker_container_id=docker_id
                ).one_or_none()
            if container is None and name:
                container = Container.query.filter_by(
                    server_id=server.id, name=name
                ).one_or_none()
            if container is None:
                continue
            raw_status = str(item.get("status") or "").strip().lower()
            try:
                container.status = ContainerStatus(raw_status)
            except ValueError:
                pass
            container.last_cpu_percent = max(0.0, _number_from(item, "cpu_percent"))
            container.last_ram_mb = max(0.0, _number_from(item, "ram_mb"))
            container.last_storage_mb = max(0.0, _number_from(item, "storage_mb"))
            container.last_seen_at = utcnow()

    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "heartbeat_interval": int(request_heartbeat_interval()),
            "poll_interval": int(request_poll_interval()),
            "server_id": server.id,
        }
    )


def request_heartbeat_interval() -> int:
    from flask import current_app

    return int(current_app.config.get("AGENT_HEARTBEAT_INTERVAL", 30))


def request_poll_interval() -> int:
    from flask import current_app

    return int(current_app.config.get("AGENT_POLL_INTERVAL", 5))


def _number_from(item: dict, key: str) -> float:
    try:
        return float(item.get(key) or 0)
    except (TypeError, ValueError):
        return 0.0


@bp.get("/tasks/next")
def next_task():
    agent, _server = _signed_context()
    task = claim_next_task(agent)
    if task is None:
        db.session.commit()
        return "", 204
    if task.deployment is not None and task.task_type.value == "deploy":
        from ..models import DeploymentStatus, WebsiteStatus

        task.deployment.status = DeploymentStatus.BUILDING
        task.deployment.started_at = task.started_at or utcnow()
        if task.website is not None:
            task.website.status = WebsiteStatus.BUILDING
            task.website.status_detail = (
                f"Deployment #{task.deployment.number} is running on the agent."
            )
        db.session.commit()
    return jsonify(task_payload_for_agent(task))


def _task_for_agent(
    agent: ServerAgent,
    task_id: str,
    *,
    allow_terminal: bool = False,
    for_update: bool = False,
) -> AgentTask:
    query = AgentTask.query.filter_by(id=task_id, agent_id=agent.id)
    if for_update:
        query = query.with_for_update()
    task = query.one_or_none()
    if task is None:
        raise NotFoundError("Agent task not found.")
    allowed = {TaskStatus.CLAIMED, TaskStatus.RUNNING}
    if allow_terminal:
        allowed.update({TaskStatus.SUCCEEDED, TaskStatus.FAILED})
    if task.status not in allowed:
        raise ConflictError("This task can no longer be updated.")
    return task


@bp.post("/tasks/<task_id>/logs")
def task_logs(task_id: str):
    agent, _server = _signed_context()
    task = _task_for_agent(agent, task_id)
    data = _json_body()
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValidationError("entries must be a list.")
    if task.deployment is None:
        db.session.commit()
        return jsonify({"stored": 0})
    stored = append_logs(task.deployment, entries)
    task.status = TaskStatus.RUNNING
    db.session.commit()
    return jsonify({"stored": stored})


@bp.post("/tasks/<task_id>/result")
def task_result(task_id: str):
    agent, _server = _signed_context()
    task = _task_for_agent(agent, task_id, allow_terminal=True, for_update=True)
    if task.status in {TaskStatus.SUCCEEDED, TaskStatus.FAILED}:
        return jsonify({"ok": True, "already_completed": True})
    data = _json_body()
    succeeded = data.get("success")
    if not isinstance(succeeded, bool):
        raise ValidationError("success must be a boolean.")
    result = data.get("result") or {}
    error = data.get("error")
    if result is not None and not isinstance(result, dict):
        raise ValidationError("result must be an object.")
    if error is not None and not isinstance(error, str):
        raise ValidationError("error must be a string.")
    task.started_at = task.started_at or utcnow()
    apply_task_result(task, succeeded=succeeded, result=result, error=error)
    logger.info(
        "Agent task %s (%s) completed success=%s",
        task.id,
        task.task_type.value,
        succeeded,
    )
    return jsonify({"ok": True})
