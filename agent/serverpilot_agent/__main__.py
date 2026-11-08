"""Agent process entrypoint."""

from __future__ import annotations

import logging
import os
import secrets
import signal
import socket
import sys
import threading
from pathlib import Path

from . import __version__
from .client import AgentError, AuthenticationError, PanelClient
from .executor import (
    TaskExecutor,
    container_snapshot,
    docker_available,
    system_capabilities,
    system_metrics,
)

logger = logging.getLogger("serverpilot_agent")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_uid(path: Path) -> str:
    configured = (os.getenv("AGENT_UID") or "").strip()
    if configured:
        return configured
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    hostname = socket.gethostname().replace(" ", "-")[:40]
    uid = f"agent-{hostname}-{secrets.token_hex(4)}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(uid, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return uid


def _register(
    client: PanelClient, *, uid: str, name: str, hostname: str, work_dir: Path
) -> None:
    capabilities = system_capabilities(work_dir)
    client.register(
        agent_uid=uid,
        name=name,
        hostname=hostname,
        capabilities=capabilities,
    )
    logger.info("Registered agent %s with the panel", uid)


def main() -> int:
    logging.basicConfig(
        level=os.getenv("AGENT_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    base_url = (os.getenv("SERVERPILOT_API_URL") or "").strip()
    if not base_url:
        logger.error("SERVERPILOT_API_URL is required")
        return 2
    if not docker_available():
        logger.error("Docker CLI is required on the agent host")
        return 2

    work_dir = Path(os.getenv("AGENT_WORK_DIR", "/var/lib/serverpilot"))
    work_dir.mkdir(parents=True, exist_ok=True)
    state_dir = Path(os.getenv("AGENT_STATE_DIR", str(work_dir / "agent")))
    state_dir.mkdir(parents=True, exist_ok=True)
    key_file = Path(os.getenv("AGENT_KEY_FILE", str(state_dir / "credentials.json")))
    uid_file = Path(os.getenv("AGENT_UID_FILE", str(state_dir / "agent_uid")))
    hostname = (os.getenv("AGENT_HOSTNAME") or socket.gethostname()).strip().lower()
    name = (os.getenv("AGENT_NAME") or hostname).strip()[:120]
    heartbeat_interval = max(10, int(os.getenv("AGENT_HEARTBEAT_INTERVAL", "30")))
    poll_interval = max(1, int(os.getenv("AGENT_POLL_INTERVAL", "5")))

    client = PanelClient(
        base_url,
        key_file,
        os.getenv("AGENT_BOOTSTRAP_TOKEN"),
        enrollment_token=os.getenv("AGENT_ENROLLMENT_TOKEN"),
        timeout=(10, 120),
    )
    uid = _load_uid(uid_file)
    if not client.key_id or not client.secret:
        try:
            _register(client, uid=uid, name=name, hostname=hostname, work_dir=work_dir)
        except Exception as exc:  # noqa: BLE001 - startup must report any failure
            logger.error("Agent registration failed: %s", exc)
            return 2

    executor = TaskExecutor(
        client,
        work_dir=work_dir,
        proxy_dir=Path(os.getenv("AGENT_PROXY_DIR", "/etc/nginx/conf.d/serverpilot")),
        docker_network=os.getenv("AGENT_DOCKER_NETWORK", "serverpilot-apps"),
        proxy_enabled=_env_bool("AGENT_PROXY_ENABLED", True),
        nginx_sudo=_env_bool("AGENT_NGINX_SUDO", True),
    )
    stop_event = threading.Event()

    def _stop(_signum, _frame):
        logger.info("Stopping agent")
        stop_event.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    def heartbeat_loop() -> None:
        while not stop_event.is_set():
            try:
                containers = container_snapshot()
                metrics = system_metrics(work_dir)
                metrics["container_count"] = len(containers)
                client.heartbeat(
                    version=__version__,
                    capabilities=system_capabilities(work_dir),
                    metrics=metrics,
                    containers=containers,
                )
            except AuthenticationError:
                logger.error(
                    "Heartbeat authentication failed; re-registering is required"
                )
            except Exception:
                logger.exception("Heartbeat failed")
            stop_event.wait(heartbeat_interval)

    thread = threading.Thread(target=heartbeat_loop, name="heartbeat", daemon=True)
    thread.start()
    logger.info("ServerPilot agent %s started for %s", __version__, base_url)

    while not stop_event.is_set():
        try:
            task = client.next_task()
            if task is None:
                stop_event.wait(poll_interval)
                continue
            logger.info("Executing task %s (%s)", task.get("id"), task.get("type"))
            executor.execute(task)
        except AuthenticationError:
            logger.error("Agent authentication failed; attempting re-registration")
            try:
                _register(
                    client, uid=uid, name=name, hostname=hostname, work_dir=work_dir
                )
            except Exception as exc:  # noqa: BLE001 - retry loop boundary
                logger.error("Re-registration failed: %s", exc)
                stop_event.wait(heartbeat_interval)
        except AgentError as exc:
            logger.error("Agent task error: %s", exc)
            stop_event.wait(poll_interval)
        except Exception:
            logger.exception("Unexpected agent error")
            stop_event.wait(poll_interval)

    thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
