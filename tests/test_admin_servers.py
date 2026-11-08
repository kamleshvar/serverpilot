from __future__ import annotations

from contextlib import contextmanager

import pytest
from flask import g
from werkzeug.security import generate_password_hash

from serverpilot.blueprints import admin_servers
from serverpilot.errors import AuthenticationRequired
from serverpilot.extensions import db
from serverpilot.models import (
    AgentCredential,
    AgentEnrollment,
    AgentStatus,
    ScanStatus,
    Server,
    ServerAgent,
    ServerApprovalStatus,
    ServerConnectionStatus,
    ServerResourceHistory,
    ServerScan,
    ServerStatus,
    UserRole,
)
from serverpilot.services.agent_enrollment import (
    consume_enrollment_token,
    issue_enrollment_token,
)
from serverpilot.services.server_monitoring import refresh_server_health
from serverpilot.utils import utcnow
from tests.factories import make_user, sign_in


def _admin_client(app, client):
    app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash("correct-password")
    admin = make_user("admin@example.com", role=UserRole.ADMIN)
    db.session.commit()
    response = client.post(
        "/techorigin/login",
        data={"passcode": "correct-password"},
    )
    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert "admin_user_id" in sess, sess
        assert "_user_id" not in sess, sess
    g.pop("_login_user", None)
    return admin


def _make_server(*, name="app-one", hostname="10.0.0.10", **overrides):
    values = {
        "name": name,
        "hostname": hostname,
        "approval_status": ServerApprovalStatus.PENDING,
        "connection_status": ServerConnectionStatus.CONNECTED,
        "scan_status": ScanStatus.PENDING,
        "status": ServerStatus.PROVISIONING,
    }
    values.update(overrides)
    server = Server(**values)
    db.session.add(server)
    db.session.commit()
    return server


def _scan_payload():
    return {
        "hostname": "app-one",
        "operating_system": {
            "pretty_name": "Ubuntu 24.04 LTS",
            "id": "ubuntu",
            "version": "24.04",
        },
        "hardware": {
            "cpu_model": "Test CPU",
            "architecture": "x86_64",
            "cpu_cores": "4",
            "total_ram_mb": 4096,
            "available_ram_mb": 2048,
            "disk": {
                "total_bytes": 50_000_000_000,
                "used_bytes": 10_000_000_000,
                "available_bytes": 40_000_000_000,
                "percent": 20.0,
            },
        },
        "software": {
            "docker": {"status": "running", "version": "27.0.0"},
            "nginx": {"status": "running", "version": "1.26.0"},
            "python": {"status": "installed", "version": "3.12.3"},
            "git": {"status": "installed", "version": "2.43.0"},
            "gunicorn": {"status": "not_installed", "version": None},
            "services": {"docker": "active", "nginx": "active"},
            "containers": [],
        },
        "network": {
            "interfaces": [{"name": "eth0", "address": "10.0.0.10/24"}],
            "public_ip": None,
            "listening_ports": [22, 80, 443],
        },
        "hosting": {"nginx_files": [], "nginx_server_names": [], "directories": []},
        "warnings": [],
        "errors": [],
    }


def test_server_pages_require_admin_and_render(app, client):
    normal = make_user("user@example.com")
    db.session.commit()
    sign_in(client, normal)
    blocked = client.get("/techorigin/servers/")
    assert blocked.status_code == 302
    assert blocked.headers["Location"].startswith("/techorigin/login")

    _admin_client(app, client)
    listing = client.get("/techorigin/servers/")
    assert listing.status_code == 200, (
        listing.status_code,
        listing.headers.get("Location"),
    )
    assert b"Servers &amp; agents" in listing.data
    assert b"No servers connected" in listing.data

    form_page = client.get("/techorigin/servers/add")
    assert form_page.status_code == 200
    assert b"Connect a server" in form_page.data
    assert b'name="private_key"' in form_page.data


def test_add_server_uses_ssh_session_without_persisting_the_key(
    app, client, monkeypatch
):
    _admin_client(app, client)

    class FakeSession:
        address = "10.0.0.10"
        fingerprint = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

    @contextmanager
    def fake_connect(_credentials):
        yield FakeSession()

    monkeypatch.setattr(admin_servers, "connect", fake_connect)
    private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-material\n-----END OPENSSH PRIVATE KEY-----"
    response = client.post(
        "/techorigin/servers/connect",
        data={
            "name": "app-one",
            "hostname": "10.0.0.10",
            "ssh_port": "22",
            "ssh_username": "ubuntu",
            "auth_method": "private_key",
            "private_key": private_key,
            "key_passphrase": "",
            "host_key_fingerprint": "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "sudo_password": "",
            "auto_scan": "",
        },
    )
    assert response.status_code == 302
    server = Server.query.filter_by(hostname="10.0.0.10").one()
    assert server.connection_status == ServerConnectionStatus.CONNECTED
    assert server.approval_status == ServerApprovalStatus.PENDING
    assert response.headers["Location"] == f"/techorigin/servers/{server.id}"
    assert "private_key" not in Server.__table__.columns
    assert private_key not in (server.last_error or "")


def test_invalid_target_is_rejected_before_creating_a_server(app, client):
    _admin_client(app, client)
    response = client.post(
        "/techorigin/servers/connect",
        data={
            "name": "loopback",
            "hostname": "127.0.0.1",
            "ssh_port": "22",
            "ssh_username": "ubuntu",
            "auth_method": "private_key",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
            "host_key_fingerprint": "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        },
    )
    assert response.status_code == 422
    assert b"Loopback" in response.data or b"loopback" in response.data
    assert Server.query.count() == 0


def test_server_detail_and_scan_pages_render_scan_history_and_findings(app, client):
    _admin_client(app, client)
    server = _make_server(
        approval_status=ServerApprovalStatus.APPROVED,
        scan_status=ScanStatus.SUCCEEDED,
        status=ServerStatus.ONLINE,
        operating_system="Ubuntu 24.04 LTS",
    )
    scan = ServerScan(
        server_id=server.id,
        status=ScanStatus.SUCCEEDED,
        scan_results=_scan_payload(),
        warnings=["Gunicorn is not installed."],
        errors=[],
        scanned_at=utcnow(),
    )
    db.session.add(scan)
    db.session.add(
        ServerResourceHistory(
            server_id=server.id,
            cpu_usage=10.5,
            ram_usage=25.0,
            storage_usage=20.0,
            recorded_at=utcnow(),
        )
    )
    db.session.commit()

    listing = client.get("/techorigin/servers")
    assert listing.status_code == 200
    assert b"app-one" in listing.data

    detail = client.get(f"/techorigin/servers/{server.id}")
    assert detail.status_code == 200
    assert b"Resource history" in detail.data
    assert b"Ubuntu 24.04 LTS" in detail.data
    assert b"Gunicorn is not installed." in detail.data
    assert b"Install agent" in detail.data

    report = client.get(f"/techorigin/servers/scan/{server.id}")
    assert report.status_code == 200
    assert b"Scan report" in report.data
    assert b"Ubuntu 24.04 LTS" in report.data
    assert b"Listening ports" in report.data


def test_approve_requires_a_successful_scan_and_sets_default(app, client):
    _admin_client(app, client)
    server = _make_server(scan_status=ScanStatus.PENDING)
    denied = client.post(f"/techorigin/servers/{server.id}/approve")
    assert denied.status_code == 302
    assert (
        db.session.get(Server, server.id).approval_status
        == ServerApprovalStatus.PENDING
    )

    server.scan_status = ScanStatus.SUCCEEDED
    db.session.commit()
    response = client.post(f"/techorigin/servers/{server.id}/approve")
    assert response.status_code == 302
    refreshed = db.session.get(Server, server.id)
    assert refreshed.approval_status == ServerApprovalStatus.APPROVED
    assert refreshed.is_default is True


def test_rejecting_a_server_revokes_its_agent_credentials(app, client):
    _admin_client(app, client)
    server = _make_server(status=ServerStatus.ONLINE)
    agent = ServerAgent(
        server_id=server.id,
        name="agent-one",
        agent_uid="agent-revoke-test",
        status=AgentStatus.ACTIVE,
        last_seen_at=utcnow(),
    )
    db.session.add(agent)
    db.session.flush()
    credential = AgentCredential(
        agent_id=agent.id,
        key_id="key-revoke-test",
        secret_encrypted="encrypted-placeholder",
    )
    db.session.add(credential)
    db.session.commit()

    response = client.post(f"/techorigin/servers/{server.id}/reject")
    assert response.status_code == 302
    refreshed = db.session.get(Server, server.id)
    assert refreshed.approval_status == ServerApprovalStatus.REJECTED
    assert refreshed.status == ServerStatus.DISABLED
    assert db.session.get(ServerAgent, agent.id).status == AgentStatus.REVOKED
    assert db.session.get(AgentCredential, credential.id).revoked_at is not None


def test_enrollment_tokens_are_single_use(app):
    admin = make_user("admin@example.com", role=UserRole.ADMIN)
    server = _make_server(hostname="10.0.0.11")
    token = issue_enrollment_token(server, created_by_id=admin.id)
    db.session.commit()
    enrollment = AgentEnrollment.query.one()
    assert enrollment.token_hash != token

    first = consume_enrollment_token(token, "agent-enroll-test")
    db.session.commit()
    assert first.used_by_agent_uid == "agent-enroll-test"
    with pytest.raises(AuthenticationRequired):
        consume_enrollment_token(token, "agent-enroll-test")


def test_enrollment_registration_links_the_agent_to_the_server(app, client):
    admin = make_user("admin@example.com", role=UserRole.ADMIN)
    server = _make_server(hostname="10.0.0.12")
    token = issue_enrollment_token(server, created_by_id=admin.id)
    db.session.commit()

    response = client.post(
        "/api/v1/agent/register",
        json={
            "agent_uid": "agent-enroll-register",
            "name": "Enrolled agent",
            "hostname": "10.0.0.12",
            "version": "0.1.0",
            "capabilities": {
                "total_ram_mb": 4096,
                "total_storage_mb": 50000,
                "total_cpu_cores": 2,
            },
        },
        headers={"X-Enrollment-Token": token},
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    refreshed = db.session.get(Server, server.id)
    assert refreshed.status == ServerStatus.ONLINE
    assert refreshed.agents[0].agent_uid == "agent-enroll-register"
    assert AgentEnrollment.query.one().used_at is not None


def test_stale_online_server_is_marked_offline(app):
    server = _make_server(
        name="stale-server",
        hostname="10.0.0.13",
        status=ServerStatus.ONLINE,
        approval_status=ServerApprovalStatus.APPROVED,
    )
    agent = ServerAgent(
        server_id=server.id,
        name="stale-agent",
        agent_uid="agent-stale",
        status=AgentStatus.ACTIVE,
        last_seen_at=utcnow(),
    )
    db.session.add(agent)
    db.session.commit()

    changed = refresh_server_health()
    db.session.refresh(server)
    db.session.refresh(agent)
    assert changed >= 1
    assert server.status == ServerStatus.OFFLINE
    assert agent.status == AgentStatus.OFFLINE


def test_rescan_requires_a_key_and_does_not_accept_missing_csrf_in_test_mode(
    app, client
):
    _admin_client(app, client)
    server = _make_server()
    response = client.post(
        f"/techorigin/servers/{server.id}/rescan",
        data={"private_key": ""},
    )
    assert response.status_code == 302
    assert response.headers["Location"] == f"/techorigin/servers/{server.id}"
