from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

from serverpilot.extensions import db
from serverpilot.models import (
    AgentStatus,
    AgentTask,
    Container,
    Deployment,
    DeploymentStatus,
    GithubInstallation,
    Server,
    ServerAgent,
    ServerApprovalStatus,
    ServerConnectionStatus,
    ServerStatus,
    TaskType,
    User,
    Website,
    WebsiteStatus,
)
from serverpilot.services.agent_tasks import enqueue_task, select_agent
from serverpilot.services.deployments import create_deployment
from tests.factories import make_user, make_website, sign_in

BOOTSTRAP = "test-agent-bootstrap-token"


def _register(client, uid="agent-1", hostname="agent-one.example.com"):
    response = client.post(
        "/api/v1/agent/register",
        json={
            "agent_uid": uid,
            "name": "Agent One",
            "hostname": hostname,
            "version": "0.1.0",
            "capabilities": {
                "total_ram_mb": 8192,
                "total_storage_mb": 102400,
                "total_cpu_cores": 4,
            },
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP},
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    with client.application.app_context():
        server = Server.query.filter_by(hostname=hostname).one()
        server.approval_status = ServerApprovalStatus.APPROVED
        db.session.commit()
    return response.get_json()


def _signed_headers(
    key_id: str, secret: str, method: str, path: str, body: bytes = b""
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    digest = hashlib.sha256(body).hexdigest()
    canonical = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{digest}"
    signature = hmac.new(
        secret.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    return {
        "X-Agent-Key": key_id,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
        "Content-Type": "application/json",
    }


def _credential(registration):
    return registration["credential"]["key_id"], registration["credential"]["secret"]


def test_agent_registration_requires_bootstrap_token(client):
    response = client.post(
        "/api/v1/agent/register",
        json={"agent_uid": "agent-x", "hostname": "host.example.com"},
        headers={"X-Bootstrap-Token": "wrong"},
    )
    assert response.status_code == 401


def test_agent_registration_heartbeat_and_nonce_replay(client, app):
    registration = _register(client)
    key_id, secret = _credential(registration)
    body = json.dumps({"version": "0.1.0", "metrics": {"ram_mb": 128}}).encode()
    headers = _signed_headers(key_id, secret, "POST", "/api/v1/agent/heartbeat", body)
    response = client.post(
        "/api/v1/agent/heartbeat",
        data=body,
        headers=headers,
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    replay = client.post(
        "/api/v1/agent/heartbeat",
        data=body,
        headers=headers,
        content_type="application/json",
    )
    assert replay.status_code == 401


def test_offline_agent_can_reconnect_with_a_heartbeat(client, app):
    registration = _register(
        client, uid="agent-recover", hostname="recover.example.com"
    )
    key_id, secret = _credential(registration)
    with app.app_context():
        server = Server.query.filter_by(hostname="recover.example.com").one()
        agent = ServerAgent.query.filter_by(agent_uid="agent-recover").one()
        server.status = ServerStatus.OFFLINE
        server.connection_status = ServerConnectionStatus.OFFLINE
        agent.status = AgentStatus.OFFLINE
        db.session.commit()
        server_id = server.id
        agent_id = agent.id

    body = json.dumps({"version": "0.1.0", "metrics": {}}).encode()
    headers = _signed_headers(key_id, secret, "POST", "/api/v1/agent/heartbeat", body)
    response = client.post(
        "/api/v1/agent/heartbeat",
        data=body,
        headers=headers,
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    with app.app_context():
        assert db.session.get(Server, server_id).status == ServerStatus.ONLINE
        assert db.session.get(ServerAgent, agent_id).status == AgentStatus.ACTIVE


def test_agent_can_poll_and_complete_a_start_task(client, app):
    registration = _register(client)
    key_id, secret = _credential(registration)
    with app.app_context():
        user = make_user("agent-task@example.com")
        website = make_website(
            user, subdomain="agenttask", status=WebsiteStatus.USER_STOPPED
        )
        website.current_deployment_id = "previous"
        website.container_name = "sp-agent-task"
        db.session.commit()
        agent = select_agent(website)
        task = enqueue_task(
            agent=agent,
            task_type=TaskType.START,
            website=website,
            payload={
                "website_id": website.id,
                "container_name": website.container_name,
            },
            created_by_id=user.id,
            idempotency_key=f"test-start-{website.id}",
        )
        db.session.commit()
        task_id = task.id
        website_id = website.id

    headers = _signed_headers(key_id, secret, "GET", "/api/v1/agent/tasks/next")
    response = client.get("/api/v1/agent/tasks/next", headers=headers)
    assert response.status_code == 200, response.get_data(as_text=True)
    payload = response.get_json()
    assert payload["id"] == task_id
    assert payload["type"] == "start"
    assert payload["signature"]

    result_body = json.dumps({"success": True, "result": {}}).encode()
    headers = _signed_headers(
        key_id, secret, "POST", f"/api/v1/agent/tasks/{task_id}/result", result_body
    )
    response = client.post(
        f"/api/v1/agent/tasks/{task_id}/result",
        data=result_body,
        headers=headers,
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    with app.app_context():
        website = db.session.get(Website, website_id)
        assert website.status == WebsiteStatus.RUNNING
        assert db.session.get(AgentTask, task_id).status.value == "succeeded"


def test_deployment_is_queued_only_after_github_verification(client, app, monkeypatch):
    registration = _register(client)
    key_id, secret = _credential(registration)
    with app.app_context():
        user = make_user("deploy@example.com")
        user.role = user.role.USER
        installation = GithubInstallation(
            installation_id=987654,
            user_id=user.id,
            account_login="deploy-user",
            status="active",
        )
        db.session.add(installation)
        website = make_website(user, subdomain="deployme", status=WebsiteStatus.PENDING)
        website.github_installation = installation
        website.repository_full_name = "deploy-user/app"
        website.branch = "main"
        website.start_command = "gunicorn app:app --bind 0.0.0.0:8000"
        website.container_name = "sp-deployme"
        db.session.commit()
        user_id = user.id
        website_id = website.id

        monkeypatch.setattr(
            "serverpilot.services.deployments.installation_token_for_commit",
            lambda *_args, **_kwargs: (
                "ghs_test_token",
                {"sha": "a" * 40, "message": "Initial commit", "author": "Deploy User"},
            ),
        )
        deployment = create_deployment(user, website)
        deployment_id = deployment.id
        assert deployment.status == DeploymentStatus.QUEUED
        assert website.status == WebsiteStatus.BUILDING

    headers = _signed_headers(key_id, secret, "GET", "/api/v1/agent/tasks/next")
    response = client.get("/api/v1/agent/tasks/next", headers=headers)
    task = response.get_json()
    assert task["type"] == "deploy"
    assert task["payload"]["installation_token"] == "ghs_test_token"
    assert "installation_token_encrypted" not in task["payload"]
    with app.app_context():
        stored_task = db.session.get(AgentTask, task["id"])
        assert "installation_token" not in stored_task.payload
        assert "installation_token_encrypted" in stored_task.payload

    logs_body = json.dumps(
        {"entries": [{"message": "Building image", "level": "info", "source": "build"}]}
    ).encode()
    headers = _signed_headers(
        key_id, secret, "POST", f"/api/v1/agent/tasks/{task['id']}/logs", logs_body
    )
    assert (
        client.post(
            f"/api/v1/agent/tasks/{task['id']}/logs",
            data=logs_body,
            headers=headers,
            content_type="application/json",
        ).status_code
        == 200
    )

    result_body = json.dumps(
        {
            "success": True,
            "result": {"container_id": "abc123", "host_port": 30001},
        }
    ).encode()
    headers = _signed_headers(
        key_id, secret, "POST", f"/api/v1/agent/tasks/{task['id']}/result", result_body
    )
    response = client.post(
        f"/api/v1/agent/tasks/{task['id']}/result",
        data=result_body,
        headers=headers,
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)

    duplicate_headers = _signed_headers(
        key_id, secret, "POST", f"/api/v1/agent/tasks/{task['id']}/result", result_body
    )
    duplicate = client.post(
        f"/api/v1/agent/tasks/{task['id']}/result",
        data=result_body,
        headers=duplicate_headers,
        content_type="application/json",
    )
    assert duplicate.status_code == 200
    assert duplicate.get_json()["already_completed"] is True

    late_logs = json.dumps({"entries": [{"message": "late"}]}).encode()
    late_headers = _signed_headers(
        key_id, secret, "POST", f"/api/v1/agent/tasks/{task['id']}/logs", late_logs
    )
    late = client.post(
        f"/api/v1/agent/tasks/{task['id']}/logs",
        data=late_logs,
        headers=late_headers,
        content_type="application/json",
    )
    assert late.status_code == 409

    with app.app_context():
        deployment = db.session.get(Deployment, deployment_id)
        website = db.session.get(Website, website_id)
        assert deployment.status == DeploymentStatus.SUCCEEDED
        assert deployment.is_current is True
        assert website.status == WebsiteStatus.RUNNING
        assert website.current_deployment_id == deployment.id
        container = Container.query.filter_by(website_id=website.id).one()
        assert container.docker_container_id == "abc123"
        assert container.status.value == "running"
        owner = db.session.get(User, user_id)

    user_client = app.test_client()
    sign_in(user_client, owner)
    page = user_client.get(f"/sites/{website_id}/deployments/{deployment_id}")
    assert page.status_code == 200
    assert b"Building image" in page.data
    detail = user_client.get(f"/sites/{website_id}")
    assert detail.status_code == 200
    assert b"Stop website" in detail.data
