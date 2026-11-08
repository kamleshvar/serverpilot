"""Administrator SSH server onboarding, discovery, enrollment and monitoring."""

from __future__ import annotations

import ipaddress
import logging
import time

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy.exc import IntegrityError

from ..decorators import admin_deployment_required, admin_required
from ..errors import AppError, NotFoundError, ValidationError
from ..extensions import db, limiter
from ..forms import ServerAddForm, ServerRescanForm
from ..models import (
    AgentCredential,
    AgentInstallStatus,
    AgentStatus,
    AgentTask,
    ScanStatus,
    Server,
    ServerAgent,
    ServerApprovalStatus,
    ServerConnectionStatus,
    ServerResourceHistory,
    ServerScan,
    ServerStatus,
    Website,
    WebsiteStatus,
)
from ..services.agent_enrollment import issue_enrollment_token
from ..services.agent_install import install_agent
from ..services.agent_tasks import expire_stale_tasks
from ..services.audit import record_admin_action
from ..services.server_monitoring import refresh_server_health
from ..services.server_ssh import (
    SSHConnectionError,
    SSHCredentials,
    apply_scan_to_server,
    connect,
    normalize_fingerprint,
    scan_server,
    validate_target,
)
from ..utils import as_utc, utcnow

logger = logging.getLogger(__name__)

bp = Blueprint("admin_servers", __name__, url_prefix="/techorigin/servers")


def _server_or_404(server_id: str) -> Server:
    server = db.session.get(Server, server_id)
    if server is None or server.deleted_at is not None:
        raise NotFoundError("Server not found.")
    return server


def _latest_scan(server: Server) -> ServerScan | None:
    return (
        ServerScan.query.filter_by(server_id=server.id)
        .order_by(ServerScan.scanned_at.desc())
        .first()
    )


def _history(server: Server) -> list[ServerResourceHistory]:
    limit = int(current_app.config.get("SERVER_MONITORING_HISTORY_LIMIT", 60))
    rows = (
        ServerResourceHistory.query.filter_by(server_id=server.id)
        .order_by(ServerResourceHistory.recorded_at.desc())
        .limit(limit)
        .all()
    )
    return list(reversed(rows))


def _audit(action: str, server: Server, *, details: dict | None = None) -> None:
    record_admin_action(
        admin=g.get("admin_user"),
        action=action,
        resource_type="server",
        resource_id=server.id,
        details=details or {},
    )


def _credentials(form, server: Server | None = None) -> SSHCredentials:
    fingerprint = (form.host_key_fingerprint.data or "").strip()
    if not fingerprint and server is not None:
        fingerprint = server.host_key_fingerprint or ""
    if server is None:
        username = (form.ssh_username.data or "").strip()
        host = (form.hostname.data or "").strip().lower().rstrip(".")
        port = int(form.ssh_port.data or 22)
    else:
        username = server.ssh_username
        host = server.hostname
        port = server.ssh_port
    return SSHCredentials(
        host=host,
        port=port,
        username=username,
        private_key=form.private_key.data or "",
        passphrase=form.key_passphrase.data or None,
        host_key_fingerprint=normalize_fingerprint(fingerprint),
    )


def _apply_connection(server: Server, session) -> None:
    server.connection_status = ServerConnectionStatus.CONNECTED
    server.last_ssh_connected_at = utcnow()
    server.last_error = None
    if session.address:
        server.ip_address = session.address[:45]
    if session.fingerprint:
        server.host_key_fingerprint = session.fingerprint[:255]
    server.touch()


def _scan_and_store(server: Server, session) -> ServerScan:
    server.scan_status = ScanStatus.RUNNING
    server.touch()
    db.session.commit()
    try:
        results = scan_server(session)
    except AppError as exc:
        server.scan_status = ScanStatus.FAILED
        server.last_scan_error = exc.message[:8000]
        server.connection_status = ServerConnectionStatus.FAILED
        server.last_error = exc.message[:8000]
        server.touch()
        db.session.commit()
        raise
    except Exception as exc:
        logger.exception("Server scan failed server_id=%s", server.id)
        server.scan_status = ScanStatus.FAILED
        server.last_scan_error = "The remote scan failed unexpectedly."
        server.connection_status = ServerConnectionStatus.FAILED
        server.last_error = server.last_scan_error
        server.touch()
        db.session.commit()
        raise SSHConnectionError("The remote server scan failed.") from exc

    warnings = [str(item)[:1000] for item in results.get("warnings", [])]
    errors = [str(item)[:1000] for item in results.get("errors", [])]
    record = ServerScan(
        server_id=server.id,
        scanned_by_id=g.get("admin_user").id if g.get("admin_user") else None,
        status=ScanStatus.SUCCEEDED,
        scan_results=results,
        warnings=warnings,
        errors=errors,
        scanned_at=utcnow(),
    )
    db.session.add(record)
    apply_scan_to_server(server, results)
    server.scan_status = ScanStatus.SUCCEEDED
    server.last_scan_error = "; ".join(errors)[:8000] or None
    server.connection_status = ServerConnectionStatus.CONNECTED
    server.last_error = None
    server.touch()
    db.session.flush()
    _audit(
        "server_scanned",
        server,
        details={
            "warnings": len(warnings),
            "errors": len(errors),
            "scan_id": record.id,
        },
    )
    db.session.commit()
    return record


def _wait_for_agent_heartbeat(server_id: str) -> bool:
    deadline = time.monotonic() + int(
        current_app.config.get("AGENT_INSTALL_WAIT_SECONDS", 60)
    )
    offline_after = int(current_app.config.get("AGENT_OFFLINE_AFTER_SECONDS", 120))
    while time.monotonic() < deadline:
        db.session.expire_all()
        server = db.session.get(Server, server_id)
        if server is None:
            return False
        agent = (
            ServerAgent.query.filter_by(server_id=server.id)
            .filter(ServerAgent.status == AgentStatus.ACTIVE)
            .order_by(ServerAgent.last_seen_at.desc())
            .first()
        )
        if agent is not None:
            seen = as_utc(agent.last_seen_at)
            if seen is not None and (utcnow() - seen).total_seconds() <= offline_after:
                return True
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    return False


def _install_agent_for_server(server: Server, session, form) -> bool:
    token = issue_enrollment_token(
        server,
        created_by_id=g.get("admin_user").id if g.get("admin_user") else None,
    )
    server.agent_install_status = AgentInstallStatus.INSTALLING
    server.touch()
    db.session.commit()
    try:
        output = install_agent(
            server,
            session,
            token,
            sudo_password=form.sudo_password.data or None,
        )
    except AppError as exc:
        db.session.rollback()
        server = db.session.get(Server, server.id)
        server.agent_install_status = AgentInstallStatus.FAILED
        server.last_error = exc.message[:8000]
        server.touch()
        _audit(
            "server_agent_install_failed", server, details={"error": exc.message[:1000]}
        )
        db.session.commit()
        raise
    except Exception as exc:
        logger.exception("Agent installation failed server_id=%s", server.id)
        db.session.rollback()
        server = db.session.get(Server, server.id)
        server.agent_install_status = AgentInstallStatus.FAILED
        server.last_error = "The agent installation failed unexpectedly."
        server.touch()
        _audit(
            "server_agent_install_failed", server, details={"error": server.last_error}
        )
        db.session.commit()
        raise SSHConnectionError("The agent installation failed.") from exc

    if not _wait_for_agent_heartbeat(server.id):
        server = db.session.get(Server, server.id) or server
        server.agent_install_status = AgentInstallStatus.FAILED
        server.last_error = (
            "The installer completed but no agent heartbeat arrived in time. "
            "Check the serverpilot-agent service on the host."
        )
        server.touch()
        _audit(
            "server_agent_install_failed",
            server,
            details={"error": "heartbeat_timeout"},
        )
        db.session.commit()
        flash(
            "The installer finished, but the agent did not check in. Inspect the "
            "serverpilot-agent systemd service before approving this server.",
            "warning",
        )
        return False

    server = db.session.get(Server, server.id) or server
    server.agent_install_status = AgentInstallStatus.INSTALLED
    server.last_error = None
    server.touch()
    _audit("server_agent_installed", server, details={"output": output[-1000:]})
    db.session.commit()
    flash(
        "Agent installed and heartbeat received. Review and approve the server.",
        "success",
    )
    return True


def _provision(server: Server, form) -> bool:
    credentials = _credentials(form)
    try:
        with connect(credentials) as session:
            _apply_connection(server, session)
            db.session.commit()
            if form.auto_scan.data or form.install_agent.data:
                _scan_and_store(server, session)
            if form.install_agent.data:
                installed = _install_agent_for_server(server, session, form)
                if installed:
                    flash(
                        "Server connected, scanned and enrolled. Review the results "
                        "before approving the server.",
                        "success",
                    )
                return installed
            if form.auto_scan.data:
                flash(
                    "Server connected and scanned. Review the results before approval.",
                    "success",
                )
            else:
                flash("Server connected. Run a scan before approving it.", "success")
            return True
    except AppError as exc:
        db.session.rollback()
        server = db.session.get(Server, server.id)
        if server is not None and not server.last_error:
            server.connection_status = ServerConnectionStatus.FAILED
            server.last_error = exc.message[:8000]
            server.touch()
            db.session.commit()
        flash(exc.message, "error")
        return False
    except Exception:
        logger.exception("Server provisioning failed server_id=%s", server.id)
        db.session.rollback()
        server = db.session.get(Server, server.id)
        if server is not None:
            server.connection_status = ServerConnectionStatus.FAILED
            server.last_error = "The server could not be provisioned."
            server.touch()
            db.session.commit()
        flash(
            "The server could not be provisioned. Check the connection details.",
            "error",
        )
        return False


def _create_server(form) -> Server:
    host = (form.hostname.data or "").strip().lower().rstrip(".")
    name = (form.name.data or "").strip()
    validate_target(host, int(form.ssh_port.data or 22))
    fingerprint = normalize_fingerprint(form.host_key_fingerprint.data)
    if (
        current_app.config.get("SSH_REQUIRE_HOST_KEY_FINGERPRINT", True)
        and not fingerprint
        and not current_app.config.get("SSH_KNOWN_HOSTS_PATH")
    ):
        raise ValidationError(
            "Enter the SSH host key SHA256 fingerprint or configure SSH_KNOWN_HOSTS_PATH."
        )
    existing = Server.query.filter(
        Server.deleted_at.is_(None),
        (Server.name == name) | (Server.hostname == host),
    ).first()
    if existing is not None:
        raise ValidationError("A server with that name or address already exists.")
    server = Server(
        name=name,
        hostname=host,
        ip_address=host if _is_ip(host) else None,
        ssh_port=int(form.ssh_port.data or 22),
        ssh_username=(form.ssh_username.data or "").strip(),
        status=ServerStatus.PROVISIONING,
        approval_status=ServerApprovalStatus.PENDING,
        connection_status=ServerConnectionStatus.UNKNOWN,
        scan_status=ScanStatus.PENDING,
        agent_install_status=AgentInstallStatus.NOT_INSTALLED,
        host_key_fingerprint=fingerprint,
    )
    db.session.add(server)
    try:
        db.session.flush()
    except IntegrityError as exc:
        db.session.rollback()
        raise ValidationError(
            "A server with that name or address already exists."
        ) from exc
    _audit("server_created", server)
    db.session.commit()
    return server


def _handle_add(form: ServerAddForm):
    if not form.validate_on_submit():
        return render_template("admin/servers/add.html", form=form), 422
    try:
        server = _create_server(form)
    except AppError as exc:
        form.hostname.errors.append(exc.message)
        return render_template("admin/servers/add.html", form=form), 422
    except Exception:
        db.session.rollback()
        logger.exception("Server creation failed")
        form.name.errors.append("The server could not be saved.")
        return render_template("admin/servers/add.html", form=form), 500
    _provision(server, form)
    return redirect(url_for("admin_servers.detail", server_id=server.id))


@bp.get("/", strict_slashes=False)
@admin_required
def index():
    refresh_server_health()
    expire_stale_tasks()
    servers = (
        Server.query.filter(Server.deleted_at.is_(None))
        .order_by(Server.is_default.desc(), Server.created_at.desc())
        .all()
    )
    scans = {server.id: _latest_scan(server) for server in servers}
    return render_template("admin/servers/list.html", servers=servers, scans=scans)


@bp.route("/add", methods=["GET", "POST"])
@admin_deployment_required
@limiter.limit(
    lambda: current_app.config.get("SERVER_PROVISION_RATE_LIMIT", "5 per minute")
)
def add():
    form = ServerAddForm()
    if form.is_submitted():
        return _handle_add(form)
    return render_template("admin/servers/add.html", form=form)


@bp.route("/connect", methods=["GET", "POST"])
@admin_deployment_required
@limiter.limit(
    lambda: current_app.config.get("SERVER_PROVISION_RATE_LIMIT", "5 per minute")
)
def connect_server():
    if request.method == "GET":
        return redirect(url_for("admin_servers.add"))
    form = ServerAddForm()
    return _handle_add(form)


@bp.get("/<server_id>")
@admin_required
def detail(server_id: str):
    server = _server_or_404(server_id)
    scan = _latest_scan(server)
    history = _history(server)
    agents = (
        ServerAgent.query.filter_by(server_id=server.id)
        .order_by(ServerAgent.last_seen_at.desc())
        .all()
    )
    recent_tasks = []
    if agents:
        recent_tasks = (
            AgentTask.query.filter_by(agent_id=agents[0].id)
            .order_by(AgentTask.created_at.desc())
            .limit(8)
            .all()
        )
    return render_template(
        "admin/servers/detail.html",
        server=server,
        scan=scan,
        history=history,
        agents=agents,
        recent_tasks=recent_tasks,
        rescan_form=ServerRescanForm(),
    )


@bp.get("/scan/<server_id>")
@admin_required
def scan(server_id: str):
    server = _server_or_404(server_id)
    record = _latest_scan(server)
    return render_template("admin/servers/scan.html", server=server, scan=record)


def _rescan_server(server: Server, form: ServerRescanForm):
    if not form.validate_on_submit():
        flash("Enter the SSH private key to reconnect and scan.", "error")
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    try:
        with connect(_credentials(form, server)) as session:
            _apply_connection(server, session)
            db.session.commit()
            _scan_and_store(server, session)
            if form.install_agent.data and _install_agent_for_server(
                server, session, form
            ):
                flash(
                    "Server rescanned and enrolled. Review the results before approval.",
                    "success",
                )
    except AppError as exc:
        db.session.rollback()
        flash(exc.message, "error")
    except Exception:
        logger.exception("Server rescan failed server_id=%s", server.id)
        db.session.rollback()
        server = db.session.get(Server, server.id) or server
        server.connection_status = ServerConnectionStatus.FAILED
        server.last_error = "The server could not be reached."
        db.session.commit()
        flash("The server could not be reached. Check the connection details.", "error")
    return redirect(url_for("admin_servers.detail", server_id=server.id))


@bp.post("/<server_id>/rescan")
@admin_deployment_required
@limiter.limit(
    lambda: current_app.config.get("SERVER_PROVISION_RATE_LIMIT", "5 per minute")
)
def rescan(server_id: str):
    return _rescan_server(_server_or_404(server_id), ServerRescanForm())


@bp.post("/<server_id>/install-agent")
@admin_deployment_required
@limiter.limit(
    lambda: current_app.config.get("SERVER_PROVISION_RATE_LIMIT", "5 per minute")
)
def install_agent_route(server_id: str):
    server = _server_or_404(server_id)
    if server.approval_status == ServerApprovalStatus.REJECTED:
        flash("Rejected servers cannot receive an agent.", "error")
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    if any(agent.is_online for agent in server.agents):
        flash("This server already has a healthy agent installed.", "warning")
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    form = ServerRescanForm()
    if not form.validate_on_submit():
        flash("Enter the SSH private key to install the agent.", "error")
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    try:
        with connect(_credentials(form, server)) as session:
            _apply_connection(server, session)
            db.session.commit()
            _install_agent_for_server(server, session, form)
    except AppError as exc:
        db.session.rollback()
        flash(exc.message, "error")
    except Exception:
        logger.exception("Agent installation failed server_id=%s", server.id)
        db.session.rollback()
        server = db.session.get(Server, server.id) or server
        server.agent_install_status = AgentInstallStatus.FAILED
        server.last_error = "The agent installation failed unexpectedly."
        db.session.commit()
        flash("The agent installation failed. Check the host and try again.", "error")
    return redirect(url_for("admin_servers.detail", server_id=server.id))


def _revoke_agents(server: Server, reason: str) -> None:
    for agent in server.agents:
        agent.status = AgentStatus.REVOKED
        agent.revoked_at = utcnow()
        agent.revoked_reason = reason
        AgentCredential.query.filter_by(agent_id=agent.id).filter(
            AgentCredential.revoked_at.is_(None)
        ).update({"revoked_at": utcnow()}, synchronize_session=False)


@bp.post("/<server_id>/approve")
@admin_deployment_required
def approve(server_id: str):
    server = _server_or_404(server_id)
    if server.scan_status != ScanStatus.SUCCEEDED:
        flash("Run a successful server scan before approving this server.", "error")
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    if server.approval_status == ServerApprovalStatus.REJECTED:
        flash(
            "Rejected servers cannot be approved without reinstalling the agent.",
            "error",
        )
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    server.approval_status = ServerApprovalStatus.APPROVED
    if not Server.query.filter(
        Server.deleted_at.is_(None), Server.is_default.is_(True)
    ).first():
        server.is_default = True
    if any(agent.is_online for agent in server.agents):
        server.status = ServerStatus.ONLINE
    server.touch()
    _audit("server_approved", server)
    db.session.commit()
    flash("Server approved. It can now receive deployments.", "success")
    return redirect(url_for("admin_servers.detail", server_id=server.id))


@bp.post("/<server_id>/reject")
@admin_deployment_required
def reject(server_id: str):
    server = _server_or_404(server_id)
    server.approval_status = ServerApprovalStatus.REJECTED
    server.status = ServerStatus.DISABLED
    server.connection_status = ServerConnectionStatus.UNKNOWN
    server.is_default = False
    _revoke_agents(server, "Server rejected by administrator")
    server.touch()
    _audit("server_rejected", server)
    db.session.commit()
    flash(
        "Server rejected. Its agent can no longer authenticate or receive tasks.",
        "warning",
    )
    return redirect(url_for("admin_servers.detail", server_id=server.id))


@bp.post("/<server_id>/delete")
@admin_deployment_required
def delete(server_id: str):
    server = _server_or_404(server_id)
    active_websites = Website.query.filter(
        Website.server_id == server.id,
        Website.status != WebsiteStatus.DELETED,
        Website.deleted_at.is_(None),
    ).count()
    if active_websites:
        flash("Move or delete the websites assigned to this server first.", "error")
        return redirect(url_for("admin_servers.detail", server_id=server.id))
    server.deleted_at = utcnow()
    server.deleted_by_id = g.get("admin_user").id if g.get("admin_user") else None
    server.status = ServerStatus.DISABLED
    server.approval_status = ServerApprovalStatus.REJECTED
    server.is_default = False
    _revoke_agents(server, "Server removed by administrator")
    server.touch()
    _audit("server_removed", server)
    db.session.commit()
    flash(
        "Server removed from the control plane. Historical scan records are retained.",
        "success",
    )
    return redirect(url_for("admin_servers.index"))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
