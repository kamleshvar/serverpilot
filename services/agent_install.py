"""Build and install the trusted ServerPilot agent over an approved SSH session."""

from __future__ import annotations

import io
import re
import secrets
import tarfile
import time
from pathlib import Path
from urllib.parse import urlparse

from flask import current_app

from ..errors import ValidationError
from ..models import Server
from .server_ssh import (
    SSHConnectionError,
    SSHSession,
    install_command_script,
    remote_preflight,
)

_PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "agent"
_SAFE_SERVICE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_. -]{1,120}$")


def _control_plane_url() -> str:
    url = str(current_app.config.get("AGENT_CONTROL_PLANE_URL") or "").rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValidationError(
            "AGENT_CONTROL_PLANE_URL must use HTTPS outside localhost."
        )
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValidationError("AGENT_CONTROL_PLANE_URL is invalid.")
    return url


def _safe_path(value: str, label: str) -> str:
    if not _SAFE_PATH.match(value or ""):
        raise ValidationError(f"{label} must be an absolute path without spaces.")
    return value


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def build_agent_bundle(server: Server, enrollment_token: str) -> bytes:
    """Create a tar.gz containing only the trusted agent source and generated config."""
    install_dir = _safe_path(
        current_app.config.get("AGENT_INSTALL_DIR", "/opt/serverpilot-agent"),
        "AGENT_INSTALL_DIR",
    )
    config_dir = _safe_path(
        current_app.config.get("AGENT_CONFIG_DIR", "/etc/serverpilot"),
        "AGENT_CONFIG_DIR",
    )
    proxy_dir = _safe_path(
        current_app.config.get("AGENT_PROXY_DIR", "/etc/nginx/conf.d/serverpilot"),
        "AGENT_PROXY_DIR",
    )
    work_dir = _safe_path(
        current_app.config.get("AGENT_WORK_DIR", "/var/lib/serverpilot"),
        "AGENT_WORK_DIR",
    )
    backup_dir = _safe_path(
        current_app.config.get("AGENT_BACKUP_DIR", f"{work_dir}/backups"),
        "AGENT_BACKUP_DIR",
    )
    service_user = current_app.config.get("AGENT_SERVICE_USER", "serverpilot")
    if not _SAFE_SERVICE_USER.match(service_user):
        raise ValidationError("AGENT_SERVICE_USER is invalid.")
    api_url = _control_plane_url()
    name = re.sub(r"[^A-Za-z0-9_. -]", "-", server.name or server.hostname)[:120]
    if not _SAFE_NAME.match(name):
        name = "serverpilot-agent"
    docker_network = re.sub(
        r"[^A-Za-z0-9_.-]",
        "-",
        current_app.config.get("AGENT_DOCKER_NETWORK", "serverpilot-apps"),
    )[:64]
    env_lines = [
        f"SERVERPILOT_API_URL={api_url}",
        f"AGENT_ENROLLMENT_TOKEN={enrollment_token}",
        f"AGENT_UID=agent-{server.id}",
        f"AGENT_NAME={name}",
        f"AGENT_HOSTNAME={server.hostname}",
        f"AGENT_WORK_DIR={work_dir}",
        f"AGENT_BACKUP_DIR={backup_dir}",
        f"AGENT_PROXY_DIR={proxy_dir}",
        "AGENT_PROXY_ENABLED=true",
        "AGENT_NGINX_SUDO=true",
        f"AGENT_DOCKER_NETWORK={docker_network}",
        f"AGENT_HEARTBEAT_INTERVAL={int(current_app.config.get('AGENT_HEARTBEAT_INTERVAL', 30))}",
        f"AGENT_POLL_INTERVAL={int(current_app.config.get('AGENT_POLL_INTERVAL', 5))}",
        "AGENT_LOG_LEVEL=INFO",
    ]
    env_text = "\n".join(env_lines) + "\n"
    requirements = "psutil>=6.0,<8\nrequests>=2.32,<3\n"

    unit = f"""[Unit]
Description=ServerPilot deployment agent
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=simple
User={service_user}
Group={service_user}
SupplementaryGroups=docker
WorkingDirectory={install_dir}
EnvironmentFile={config_dir}/agent.env
ExecStart={install_dir}/.venv/bin/python -m serverpilot_agent
Restart=always
RestartSec=5
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths={work_dir} {proxy_dir}
ReadOnlyPaths={config_dir}

[Install]
WantedBy=multi-user.target
"""

    install_script = """#!/usr/bin/env bash
set -euo pipefail
umask 027

if [ "$(id -u)" -ne 0 ]; then
  echo "The ServerPilot installer must run as root." >&2
  exit 1
fi

BUNDLE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="@@INSTALL_DIR@@"
CONFIG_DIR="@@CONFIG_DIR@@"
PROXY_DIR="@@PROXY_DIR@@"
WORK_DIR="@@WORK_DIR@@"
SERVICE_USER="@@SERVICE_USER@@"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required." >&2
  exit 1
fi
if ! command -v nginx >/dev/null 2>&1; then
  echo "nginx is required." >&2
  exit 1
fi
if ! python3 -c 'import venv' >/dev/null 2>&1; then
  echo "The python3-venv package is required." >&2
  exit 1
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$WORK_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker "$SERVICE_USER"
fi

install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$WORK_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0770 "$PROXY_DIR"
rm -rf "$INSTALL_DIR/serverpilot_agent" "$INSTALL_DIR/.venv"
cp -a "$BUNDLE/serverpilot_agent" "$INSTALL_DIR/serverpilot_agent"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --no-cache-dir --disable-pip-version-check -r "$BUNDLE/requirements.txt"

install -m 0640 -o root -g "$SERVICE_USER" "$BUNDLE/agent.env" "$CONFIG_DIR/agent.env"
install -m 0644 -o root -g root "$BUNDLE/serverpilot-agent.service" /etc/systemd/system/serverpilot-agent.service

NGINX_BIN="$(command -v nginx || true)"
if [ -n "$NGINX_BIN" ] && [ -x "$NGINX_BIN" ]; then
  cat > /etc/sudoers.d/serverpilot-agent <<EOF
Cmnd_Alias SERVERPILOT_NGINX = $NGINX_BIN -t, $NGINX_BIN -s reload
$SERVICE_USER ALL=(root) NOPASSWD: SERVERPILOT_NGINX
EOF
  chmod 0440 /etc/sudoers.d/serverpilot-agent
  visudo -cf /etc/sudoers.d/serverpilot-agent >/dev/null
fi

systemctl daemon-reload
systemctl enable --now serverpilot-agent.service
sleep 2
systemctl is-active --quiet serverpilot-agent.service
echo "ServerPilot agent installed and started."
"""
    install_script = (
        install_script.replace("@@INSTALL_DIR@@", install_dir)
        .replace("@@CONFIG_DIR@@", config_dir)
        .replace("@@PROXY_DIR@@", proxy_dir)
        .replace("@@WORK_DIR@@", work_dir)
        .replace("@@SERVICE_USER@@", service_user)
    )

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", compresslevel=9) as tar:
        package = _PACKAGE_ROOT / "serverpilot_agent"
        if not package.is_dir():
            raise ValidationError("The local agent package is missing.")
        for path in sorted(package.rglob("*")):
            if (
                "__pycache__" in path.parts
                or path.suffix == ".pyc"
                or not path.is_file()
            ):
                continue
            relative = path.relative_to(package)
            _add_bytes(
                tar, f"serverpilot_agent/{relative.as_posix()}", path.read_bytes()
            )
        _add_bytes(tar, "requirements.txt", requirements.encode())
        _add_bytes(tar, "agent.env", env_text.encode())
        _add_bytes(tar, "serverpilot-agent.service", unit.encode())
        _add_bytes(tar, "install.sh", install_script.encode(), mode=0o700)
    return output.getvalue()


def install_agent(
    server: Server,
    session: SSHSession,
    enrollment_token: str,
    *,
    sudo_password: str | None = None,
) -> str:
    """Preflight, upload and install the agent; return sanitized installer output."""
    remote_preflight(session, sudo_password=sudo_password)
    bundle = build_agent_bundle(server, enrollment_token)
    remote_dir = f"/tmp/serverpilot-agent-{secrets.token_hex(16)}"
    archive = f"{remote_dir}/bundle.tar.gz"
    try:
        session.run(f"mkdir -p -- {remote_dir}", timeout=15)
        session.upload(bundle, archive)
        extract = session.run(
            f"tar -xzf {archive} -C {remote_dir} && chmod 700 {remote_dir}/install.sh",
            timeout=60,
        )
        if extract.exit_status != 0:
            raise SSHConnectionError(
                "The agent bundle could not be unpacked on the server."
            )
        command, stdin_text = install_command_script(remote_dir, sudo_password)
        result = session.run(command, timeout=600, stdin_text=stdin_text)
        output = (result.stdout + "\n" + result.stderr).strip()[-12000:]
        output = output.replace(enrollment_token, "[enrollment-token-redacted]")
        if result.exit_status != 0:
            raise SSHConnectionError(
                "The agent installer failed on the server: "
                + (output[-4000:] or "no output")
            )
        return output[-8000:]
    finally:
        session.cleanup(remote_dir)
