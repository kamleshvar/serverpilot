"""Signed HTTPS client used by the deployment agent."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from . import __version__


class AgentError(RuntimeError):
    pass


class AuthenticationError(AgentError):
    pass


def canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


class PanelClient:
    def __init__(
        self,
        base_url: str,
        key_file: Path,
        bootstrap_token: str | None,
        *,
        enrollment_token: str | None = None,
        timeout: tuple[float, float] = (10, 60),
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" and parsed.hostname not in {
            "127.0.0.1",
            "localhost",
        }:
            raise AgentError("SERVERPILOT_API_URL must use HTTPS outside localhost.")
        self.base_url = base_url.rstrip("/")
        self.key_file = key_file
        self.bootstrap_token = bootstrap_token or ""
        self.enrollment_token = enrollment_token or ""
        self.timeout = timeout
        self.key_id: str | None = None
        self.secret: str | None = None
        self.agent_uid: str | None = None
        self._load_credentials()

    def _load_credentials(self) -> None:
        if not self.key_file.exists():
            return
        try:
            data = json.loads(self.key_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AgentError(f"Cannot read agent credentials: {exc}") from exc
        self.key_id = data.get("key_id")
        self.secret = data.get("secret")
        self.agent_uid = data.get("agent_uid")

    def _save_credentials(self, key_id: str, secret: str, agent_uid: str) -> None:
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "key_id": key_id,
            "secret": secret,
            "agent_uid": agent_uid,
        }
        temp = self.key_file.with_suffix(".tmp")
        temp.write_text(json.dumps(payload), encoding="utf-8")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        temp.replace(self.key_file)
        self.key_id = key_id
        self.secret = secret
        self.agent_uid = agent_uid

    def register(
        self, *, agent_uid: str, name: str, hostname: str, capabilities: dict
    ) -> dict:
        if not self.enrollment_token and not self.bootstrap_token:
            raise AuthenticationError(
                "No agent credentials are stored and no enrollment/bootstrap token is set."
            )
        headers = {"User-Agent": f"ServerPilot-Agent/{__version__}"}
        if self.enrollment_token:
            headers["X-Enrollment-Token"] = self.enrollment_token
        else:
            headers["X-Bootstrap-Token"] = self.bootstrap_token
        response = requests.post(
            f"{self.base_url}/api/v1/agent/register",
            json={
                "agent_uid": agent_uid,
                "name": name,
                "hostname": hostname,
                "version": __version__,
                "capabilities": capabilities,
            },
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code != 201:
            raise AuthenticationError(
                f"Agent registration failed ({response.status_code}): {response.text[:500]}"
            )
        data = response.json()
        credential = data["credential"]
        self._save_credentials(
            credential["key_id"], credential["secret"], data["agent"]["uid"]
        )
        return data

    def _headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        if not self.key_id or not self.secret:
            raise AuthenticationError("The agent has no valid credentials.")
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        digest = hashlib.sha256(body).hexdigest()
        canonical = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{digest}"
        signature = hmac.new(
            self.secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        headers = {
            "X-Agent-Key": self.key_id,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": signature,
            "User-Agent": f"ServerPilot-Agent/{__version__}",
        }
        if body:
            headers["Content-Type"] = "application/json"
        return headers

    def request(
        self, method: str, path: str, payload: dict | None = None
    ) -> requests.Response:
        body = canonical_json(payload) if payload is not None else b""
        response = requests.request(
            method,
            f"{self.base_url}{path}",
            data=body or None,
            headers=self._headers(method, path, body),
            timeout=self.timeout,
        )
        if response.status_code == 401:
            raise AuthenticationError(response.text[:500])
        return response

    def heartbeat(
        self, *, version: str, capabilities: dict, metrics: dict, containers: list[dict]
    ) -> None:
        response = self.request(
            "POST",
            "/api/v1/agent/heartbeat",
            {
                "version": version,
                "capabilities": capabilities,
                "metrics": metrics,
                "containers": containers,
            },
        )
        if response.status_code != 200:
            raise AgentError(
                f"Heartbeat rejected ({response.status_code}): {response.text[:500]}"
            )

    def next_task(self) -> dict | None:
        response = self.request("GET", "/api/v1/agent/tasks/next")
        if response.status_code == 204:
            return None
        if response.status_code != 200:
            raise AgentError(
                f"Task poll failed ({response.status_code}): {response.text[:500]}"
            )
        return response.json()

    def logs(self, task_id: str, entries: list[dict]) -> None:
        if not entries:
            return
        response = self.request(
            "POST", f"/api/v1/agent/tasks/{task_id}/logs", {"entries": entries}
        )
        if response.status_code != 200:
            raise AgentError(
                f"Log upload failed ({response.status_code}): {response.text[:500]}"
            )

    def result(
        self, task_id: str, *, success: bool, result: dict, error: str | None
    ) -> None:
        response = self.request(
            "POST",
            f"/api/v1/agent/tasks/{task_id}/result",
            {"success": success, "result": result, "error": error},
        )
        if response.status_code != 200:
            raise AgentError(
                f"Task result rejected ({response.status_code}): {response.text[:500]}"
            )
