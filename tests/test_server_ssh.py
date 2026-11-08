from __future__ import annotations

from serverpilot.services.server_ssh import CommandResult, remote_preflight


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def run(
        self, command: str, *, timeout: int | None = None, stdin_text: str | None = None
    ):
        self.calls.append((command, stdin_text))
        if command == "nginx -t":
            return CommandResult("", "permission denied", 1)
        if command == "sudo -S -p '' nginx -t":
            return CommandResult("configuration file test is successful", "", 0)
        return CommandResult("ok", "", 0)


def test_remote_preflight_uses_sudo_for_nginx_when_password_is_supplied(app):
    session = FakeSession()

    result = remote_preflight(session, sudo_password="server-secret")

    assert result["nginx"]["exit_status"] == 0
    assert ("sudo -S -p '' nginx -t", "server-secret\n") in session.calls
