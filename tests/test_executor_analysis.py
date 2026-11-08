"""Agent-side source analysis and Dockerfile generation tests."""

from __future__ import annotations

import pytest

agent_executor = pytest.importorskip("agent")
from agent.serverpilot_agent.executor import TaskExecutor


def _executor(tmp_path):
    return TaskExecutor(
        None,
        work_dir=tmp_path,
        proxy_dir=tmp_path / "proxy",
        docker_network="serverpilot-apps-test",
        proxy_enabled=False,
    )
