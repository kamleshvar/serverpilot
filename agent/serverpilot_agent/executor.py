"""Real Docker task execution for the ServerPilot agent."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

import requests

from .client import AgentError, PanelClient, canonical_json

logger = logging.getLogger(__name__)

_FQDN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
GITHUB_API = "https://api.github.com"


def _run(
    args: list[str],
    *,
    timeout: int = 300,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    if check and result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()[-4000:]
        raise AgentError(f"Command failed ({args[0]}): {message}")
    return result


class TaskExecutor:
    def __init__(
        self,
        client: PanelClient,
        *,
        work_dir: Path,
        proxy_dir: Path,
        docker_network: str,
        proxy_enabled: bool = True,
        nginx_sudo: bool = True,
    ) -> None:
        self.client = client
        self.work_dir = work_dir
        self.proxy_dir = proxy_dir
        self.docker_network = docker_network
        self.proxy_enabled = proxy_enabled
        self.nginx_sudo = nginx_sudo
        self.nginx_bin = os.getenv("AGENT_NGINX_BIN", "nginx")
        self._log_buffer: list[dict] = []
        self._task_id: str | None = None

    def verify(self, task: dict) -> None:
        signature = task.get("signature") or ""
        secret = self.client.secret or ""
        expected = hmac.new(
            secret.encode(), canonical_json(task.get("payload") or {}), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise AgentError("Task signature verification failed.")

    def execute(self, task: dict) -> None:
        self._task_id = task["id"]
        self._log_buffer = []
        try:
            self.verify(task)
            task_type = task["type"]
            payload = task.get("payload") or {}
            handler = {
                "deploy": self._deploy,
                "start": self._start,
                "stop": self._stop,
                "restart": self._restart,
                "remove": self._remove,
                "delete": self._remove,
                "collect_logs": self._collect_logs,
                "backup": self._backup,
                "restore": self._restore,
            }.get(task_type)
            if handler is None:
                raise AgentError(f"Unsupported task type: {task_type}")
            result = handler(payload)
        except Exception as exc:
            logger.exception("Task %s failed", task["id"])
            self._flush()
            self.client.result(
                task["id"], success=False, result={}, error=str(exc)[:8000]
            )
        else:
            self._flush()
            self.client.result(
                task["id"], success=True, result=result or {}, error=None
            )
        finally:
            self._task_id = None

    def _log(
        self, message: str, *, level: str = "info", source: str = "deployment"
    ) -> None:
        line = (message or "").strip()
        if not line:
            return
        for segment in line.splitlines()[:200]:
            self._log_buffer.append(
                {"message": segment[:19000], "level": level, "source": source}
            )
        if len(self._log_buffer) >= 20:
            self._flush()

    def _flush(self) -> None:
        if not self._task_id or not self._log_buffer:
            return
        entries, self._log_buffer = self._log_buffer, []
        try:
            self.client.logs(self._task_id, entries)
        except Exception:
            logger.exception("Could not upload deployment logs")
            self._log_buffer = entries + self._log_buffer

    def _stream_command(
        self, args: list[str], *, source: str = "build", timeout: int = 1800
    ) -> None:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        started = time.monotonic()
        assert process.stdout is not None
        for line in process.stdout:
            self._log(line, source=source)
            if time.monotonic() - started > timeout:
                process.kill()
                raise AgentError("Docker build exceeded the agent timeout.")
        code = process.wait()
        if code != 0:
            raise AgentError(f"Docker command failed with exit code {code}.")
        self._flush()

    def _ensure_network(self) -> None:
        inspect = _run(
            ["docker", "network", "inspect", self.docker_network], check=False
        )
        if inspect.returncode != 0:
            _run(["docker", "network", "create", self.docker_network])
            self._log(f"Created Docker network {self.docker_network}.", source="system")

    def _download_source(self, payload: dict, target: Path) -> Path:
        repository = str(payload.get("repository_full_name") or "")
        sha = str(payload.get("commit_sha") or "")
        token = str(payload.get("installation_token") or "")
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repository):
            raise AgentError("The repository name is invalid.")
        if not re.match(r"^[a-f0-9]{40}$", sha):
            raise AgentError("The deployment commit is invalid.")
        if not token:
            raise AgentError("The panel did not provide a GitHub installation token.")
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        archive = target / "source.tar.gz"
        self._log(f"Fetching {repository} at {sha[:8]} from GitHub.", source="build")
        with requests.get(
            f"{GITHUB_API}/repos/{repository}/tarball/{sha}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "ServerPilot-Agent/0.1",
            },
            stream=True,
            timeout=(10, 300),
        ) as response:
            if response.status_code != 200:
                raise AgentError(
                    f"GitHub archive download failed ({response.status_code})."
                )
            with archive.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        handle.write(chunk)
        extracted = target / "extracted"
        extracted.mkdir()
        try:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(extracted, filter="data")
        except (tarfile.TarError, OSError) as exc:
            raise AgentError(
                f"The repository archive could not be extracted: {exc}"
            ) from exc
        children = [item for item in extracted.iterdir() if item.is_dir()]
        source = children[0] if len(children) == 1 else extracted
        root_directory = str(payload.get("root_directory") or "").strip().strip("/")
        if root_directory:
            source = (source / root_directory).resolve()
            if not source.is_relative_to(extracted.resolve()):
                raise AgentError("Root directory escapes the repository.")
        if not source.is_dir():
            raise AgentError("The configured root directory does not exist.")
        archive.unlink(missing_ok=True)
        return source

    def _analyze_source(self, source: Path) -> dict:
        """Analyze every kind of file in the extracted repository.

        Returns a summary used to auto-configure the build (framework,
        commands and requirements installation) and is logged into the
        deployment logs so users can see exactly what was detected.
        """
        source = source.resolve() if source.exists() else source
        analysis: dict = {
            "requirements": bool((source / "requirements.txt").is_file()),
            "pyproject": bool((source / "pyproject.toml").is_file()),
            "pipfile": bool((source / "Pipfile").is_file()),
            "package_json": bool((source / "package.json").is_file()),
            "package_lock": bool((source / "package-lock.json").is_file()),
            "yarn_lock": bool((source / "yarn.lock").is_file()),
            "dockerfile": bool((source / "Dockerfile").is_file()),
            "procfile": bool((source / "Procfile").is_file()),
            "python_entry": None,
            "app_module": None,
            "node_start": None,
            "node_build": None,
            "static_root": None,
            "detected_framework": None,
        }

        # Python entrypoint discovery: app.py > wsgi.py > main.py > run.py.
        for candidate in ("app.py", "wsgi.py", "main.py", "run.py"):
            path = source / candidate
            if not path.is_file():
                continue
            analysis["python_entry"] = candidate
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            for match in re.finditer(
                r"^(\S+)\s*=\s*\"?(Flask|FastAPI|Starlette)\(", text, re.MULTILINE
            ):
                if "." not in match.group(1):
                    analysis["app_module"] = f"{path.stem}:{match.group(1)}"
                    break
            break

        if (source / "package.json").is_file():
            try:
                data = json.loads(
                    (source / "package.json").read_text(
                        encoding="utf-8", errors="ignore"
                    )
                )
                scripts = data.get("scripts") if isinstance(data, dict) else None
                if isinstance(scripts, dict):
                    if scripts.get("start"):
                        analysis["node_start"] = "npm start"
                    elif data.get("main") and (source / str(data["main"])).is_file():
                        analysis["node_start"] = f"node {data['main']}"
                    if scripts.get("build"):
                        analysis["node_build"] = "npm run build"
            except (OSError, ValueError):
                pass

        # Static-site discovery: index.html at the root or in a common folder.
        static_candidates = [
            "index.html",
            "public/index.html",
            "www/index.html",
            "static/index.html",
            "dist/index.html",
            "build/index.html",
        ]
        for candidate in static_candidates:
            if (source / candidate).is_file():
                root = candidate.split("/")[0] if "/" in candidate else ""
                analysis["static_root"] = root
                break

        if not analysis["dockerfile"]:
            if analysis["package_json"] or analysis["yarn_lock"]:
                analysis["detected_framework"] = "node"
            elif (
                analysis["requirements"]
                or analysis["pyproject"]
                or analysis["python_entry"]
            ):
                analysis["detected_framework"] = "flask"
            elif analysis["static_root"] is not None:
                analysis["detected_framework"] = "static"
        return analysis

    def _log_analysis(self, analysis: dict) -> None:
        found = {
            "requirements.txt": analysis["requirements"],
            "pyproject.toml": analysis["pyproject"],
            "package.json": analysis["package_json"],
            "package-lock.json": analysis["package_lock"],
            "yarn.lock": analysis["yarn_lock"],
            "Procfile": analysis["procfile"],
            "Dockerfile": analysis["dockerfile"],
            "index.html": analysis["static_root"] is not None,
        }
        present = [name for name, flag in found.items() if flag]
        self._log(
            "Source analysis: "
            + (", ".join(present) if present else "no build files detected"),
            source="system",
        )
        if analysis["python_entry"]:
            self._log(
                f"Source analysis: Python entrypoint {analysis['python_entry']} (module {analysis['app_module'] or 'unknown'})",
                source="system",
            )
        if analysis["static_root"]:
            root_text = analysis["static_root"] or "repository root"
            self._log(
                f"Source analysis: static site root '{root_text}'.", source="system"
            )

    def _write_dockerfile(self, source: Path, payload: dict) -> Path:
        dockerfile_path = str(payload.get("dockerfile_path") or "").strip().strip("/")
        candidate = (
            source / dockerfile_path if dockerfile_path else source / "Dockerfile"
        )
        if candidate.is_file():
            self._log(
                f"Using repository Dockerfile at {candidate.relative_to(source)}."
            )
            return candidate
        if dockerfile_path:
            raise AgentError("The configured Dockerfile path does not exist.")

        analysis = self._analyze_source(source)
        self._log_analysis(analysis)

        framework = str(payload.get("framework") or "other").strip().lower()
        if framework in {"other", "", "auto"}:
            framework = analysis["detected_framework"] or framework
        start_command = str(payload.get("start_command") or "").strip()
        build_command = str(payload.get("build_command") or "").strip()
        internal_port = int(payload.get("internal_port") or 8000)

        if framework == "static":
            static_root = (analysis["static_root"] or "").strip("/")
            from_dir = (source / static_root) if static_root else source
            content_dir = from_dir if (from_dir / "index.html").is_file() else source
            conf = (
                "server {\n"
                "    listen 80;\n"
                "    server_name _;\n"
                "    root /usr/share/nginx/html;\n"
                "    index index.html index.htm;\n"
                "    location / { try_files $uri $uri/ /index.html; }\n"
                "    charset utf-8;\n"
                "    gzip on;\n"
                "    gzip_types text/css application/javascript application/json image/svg+xml text/plain;\n"
                "}\n"
            )
            static_conf = source / ".serverpilot-static.conf"
            static_conf.write_text(conf, encoding="utf-8")
            dockerfile = source / ".serverpilot.Dockerfile"
            dockerfile.write_text(
                "FROM nginx:1.27-alpine\n"
                "RUN rm -f /etc/nginx/conf.d/default.conf\n"
                "COPY .serverpilot-static.conf /etc/nginx/conf.d/default.conf\n"
                "COPY . /usr/share/nginx/html\n"
                "EXPOSE 80\n",
                encoding="utf-8",
            )
            self._log(
                f"Generated a static nginx image serving '{'repository root' if content_dir == source else (static_root or 'repository root')}'.",
                source="system",
            )
            return dockerfile

        if framework in {"flask", "python"}:
            if not start_command:
                start_command = self._infer_python_start(
                    source, analysis, internal_port
                )
            if not start_command:
                raise AgentError(
                    "No start command and no recognizable Python entrypoint "
                    "(app.py, wsgi.py, main.py, run.py or Procfile). Provide a "
                    "start command or a repository Dockerfile."
                )
            install_lines = []
            if analysis["requirements"]:
                install_lines.append(
                    "RUN pip install --no-cache-dir -r requirements.txt"
                )
            elif analysis["pyproject"]:
                install_lines.append(
                    "RUN pip install --no-cache-dir . || pip install --no-cache-dir .[all]"
                )
            if analysis["requirements"]:
                req_text = (
                    (source / "requirements.txt")
                    .read_text(encoding="utf-8", errors="ignore")
                    .lower()
                )
                if "gunicorn" in (start_command or "") and "gunicorn" not in req_text:
                    install_lines.append("RUN pip install --no-cache-dir gunicorn")
            content = (
                "FROM python:3.12-slim\n"
                "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                + ("\n".join(install_lines) + "\n" if install_lines else "")
                + (
                    (
                        f"RUN {json.dumps(['sh', '-lc', build_command], ensure_ascii=False)}\n"
                    )
                    if build_command
                    else ""
                )
                + f"EXPOSE {internal_port}\n"
                + f"CMD {json.dumps(['sh', '-lc', start_command], ensure_ascii=False)}\n"
            )
            dockerfile = source / ".serverpilot.Dockerfile"
            dockerfile.write_text(content, encoding="utf-8")
            self._log(
                f"Generated a Python image with start command {start_command!r}.",
                source="system",
            )
            return dockerfile

        if framework == "node":
            if not start_command:
                start_command = analysis["node_start"] or (
                    "npm start" if analysis["package_json"] else ""
                )
            if not start_command:
                raise AgentError(
                    "No start command and no recognisable Node entrypoint "
                    "(package.json start script or main). Provide a start "
                    "command or a repository Dockerfile."
                )
            install = (
                "RUN npm ci --omit=dev"
                if analysis["package_lock"]
                else "RUN npm install --omit=dev"
            )
            content = (
                "FROM node:20-alpine\n"
                "WORKDIR /app\n"
                "COPY . /app\n"
                f"{install}\n"
                + (
                    (
                        f"RUN {json.dumps(['sh', '-lc', build_command or analysis['node_build'] or 'echo'], ensure_ascii=False)}\n"
                    )
                    if (build_command or analysis["node_build"])
                    else ""
                )
                + f"EXPOSE {internal_port}\n"
                + f"CMD {json.dumps(['sh', '-lc', start_command], ensure_ascii=False)}\n"
            )
            dockerfile = source / ".serverpilot.Dockerfile"
            dockerfile.write_text(content, encoding="utf-8")
            self._log(
                f"Generated a Node image with start command {start_command!r}.",
                source="system",
            )
            return dockerfile

        raise AgentError(
            "This framework requires a repository Dockerfile. The agent builds "
            "Flask/Python, Node.js and static (HTML) websites automatically."
        )

    def _infer_python_start(
        self, source: Path, analysis: dict, internal_port: int
    ) -> str:
        """Derive a start command when the user left it empty."""
        procfile = source / "Procfile"
        if procfile.is_file():
            try:
                for line in (
                    procfile.read_text(encoding="utf-8", errors="ignore")
                ).splitlines():
                    name, _, command = line.partition(":")
                    if name.strip().lower() == "web" and command.strip():
                        return command.strip().replace("$PORT", str(internal_port))
            except OSError:
                pass
        if analysis["python_entry"] and analysis["app_module"]:
            return (
                f"gunicorn --workers 2 --threads 4 --bind 0.0.0.0:{internal_port} "
                f"{analysis['app_module']}"
            )
        if not analysis["requirements"]:
            return ""
        requirements = (
            (source / "requirements.txt")
            .read_text(encoding="utf-8", errors="ignore")
            .lower()
        )
        if (
            "gunicorn" in requirements
            and analysis["python_entry"]
            and analysis["app_module"] is None
        ):
            module = analysis["python_entry"].removesuffix(".py")
            return (
                f"gunicorn --workers 2 --threads 4 --bind 0.0.0.0:{internal_port} "
                f"{module}:app"
            )
        if analysis["python_entry"]:
            entry = source / analysis["python_entry"]
            try:
                text = entry.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            has_decorated_flask = "Flask(" in text and "__main__" in text
            if has_decorated_flask and not analysis["app_module"]:
                return f"python -u {analysis['python_entry']} --port {internal_port}"
        return ""

    def _container_port(self, container_name: str, internal_port: int) -> int:
        result = _run(
            ["docker", "port", container_name, f"{internal_port}/tcp"], check=False
        )
        if result.returncode != 0:
            raise AgentError("The container did not publish its application port.")
        line = (result.stdout or "").strip().splitlines()[0]
        try:
            return int(line.rsplit(":", 1)[1])
        except (IndexError, ValueError) as exc:
            raise AgentError("Docker returned an invalid published port.") from exc

    def _health_check(self, host_port: int, payload: dict) -> None:
        path = str(payload.get("healthcheck_path") or "/")
        if not path.startswith("/"):
            path = "/" + path
        timeout = int(payload.get("healthcheck_timeout_seconds") or 60)
        url = f"http://127.0.0.1:{host_port}{path}"
        deadline = time.monotonic() + max(10, timeout)
        last_error = ""
        while time.monotonic() < deadline:
            try:
                response = requests.get(url, timeout=3, allow_redirects=False)
                if response.status_code < 400:
                    self._log(f"Health check passed at {path}.", source="system")
                    return
                last_error = f"HTTP {response.status_code}"
            except requests.RequestException as exc:
                last_error = str(exc)[:300]
            time.sleep(2)
        raise AgentError(f"Health check failed at {path}: {last_error}")

    def _nginx(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
        command = [self.nginx_bin, *args]
        if self.nginx_sudo:
            command = ["sudo", "-n", *command]
        return _run(command, check=False, timeout=timeout)

    def _write_proxy(self, fqdn: str, host_port: int) -> None:
        if not self.proxy_enabled:
            return
        fqdn = fqdn.strip().lower()
        if not _FQDN_RE.match(fqdn) or ".." in fqdn:
            raise AgentError("The website domain is invalid for proxy configuration.")
        self.proxy_dir.mkdir(parents=True, exist_ok=True)
        target = self.proxy_dir / f"{fqdn}.conf"
        config = (
            "server {\n"
            "    listen 80;\n"
            f"    server_name {fqdn};\n"
            "    client_max_body_size 20m;\n"
            "    location / {\n"
            f"        proxy_pass http://127.0.0.1:{host_port};\n"
            "        proxy_http_version 1.1;\n"
            "        proxy_set_header Host $host;\n"
            "        proxy_set_header X-Real-IP $remote_addr;\n"
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            "        proxy_set_header X-Forwarded-Proto https;\n"
            "        proxy_set_header Upgrade $http_upgrade;\n"
            '        proxy_set_header Connection "upgrade";\n'
            "    }\n"
            "}\n"
        )
        temp = target.with_suffix(".conf.tmp")
        temp.write_text(config, encoding="utf-8")
        temp.replace(target)
        check = self._nginx("-t")
        if check.returncode != 0:
            target.unlink(missing_ok=True)
            raise AgentError(
                f"Nginx rejected the proxy configuration: {(check.stderr or '')[-2000:]}"
            )
        reload_result = self._nginx("-s", "reload")
        if reload_result.returncode != 0:
            raise AgentError(
                f"Could not reload Nginx: {(reload_result.stderr or '')[-2000:]}"
            )
        self._log(f"Proxy route for {fqdn} is active.", source="system")

    def _remove_proxy(self, fqdn: str) -> None:
        if not self.proxy_enabled or not fqdn:
            return
        fqdn = fqdn.strip().lower()
        if not _FQDN_RE.match(fqdn) or ".." in fqdn:
            raise AgentError("The website domain is invalid for proxy configuration.")
        path = self.proxy_dir / f"{fqdn}.conf"
        if path.exists():
            path.unlink()
            self._nginx("-s", "reload")

    def _deploy(self, payload: dict) -> dict:
        website_id = str(payload.get("website_id") or "")
        if not _SAFE_ID_RE.match(website_id):
            raise AgentError("The website identifier is invalid.")
        deployment_number = int(payload.get("deployment_number") or 0)
        container_name = str(payload.get("container_name") or "")
        if not _SAFE_ID_RE.match(container_name):
            raise AgentError("The container name is invalid.")
        image = str(payload.get("image_tag") or "")
        if not image:
            raise AgentError("The deployment image tag is missing.")
        self._ensure_network()
        deployment_dir = (
            self.work_dir
            / "sites"
            / website_id
            / "deployments"
            / str(deployment_number)
        )
        deployment_dir.mkdir(parents=True, exist_ok=True)
        source = self._download_source(payload, deployment_dir)
        dockerfile = self._write_dockerfile(source, payload)
        self._log(f"Building image {image}.", source="build")
        self._stream_command(
            ["docker", "build", "-f", str(dockerfile), "-t", image, str(source)],
            source="build",
        )

        existing = _run(["docker", "container", "inspect", container_name], check=False)
        if existing.returncode == 0:
            self._log(
                f"Replacing existing container {container_name}.", source="system"
            )
            _run(["docker", "rm", "-f", container_name], check=False)

        internal_port = int(payload.get("internal_port") or 8000)
        if payload.get("framework") == "static":
            internal_port = 80
        ram = int(payload.get("ram_limit_mb") or 256)
        cpu = float(payload.get("cpu_limit") or 0.5)
        volume = f"sp-{website_id.replace('-', '')[:24]}-data"
        self._log("Starting the application container.", source="system")
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                container_name,
                "--restart",
                "unless-stopped",
                "--network",
                self.docker_network,
                "--memory",
                f"{ram}m",
                "--memory-swap",
                f"{ram}m",
                "--cpus",
                str(cpu),
                "--pids-limit",
                "256",
                "--security-opt",
                "no-new-privileges:true",
                "--label",
                "serverpilot.managed=true",
                "--label",
                f"serverpilot.website_id={website_id}",
                "--label",
                f"serverpilot.deployment={deployment_number}",
                "--mount",
                f"type=volume,src={volume},dst=/data",
                "--publish",
                f"127.0.0.1::{internal_port}",
                image,
            ],
            timeout=180,
        )
        container_id = _run(
            ["docker", "inspect", "-f", "{{.Id}}", container_name]
        ).stdout.strip()
        host_port = self._container_port(container_name, internal_port)
        self._log(f"Container is listening on 127.0.0.1:{host_port}.", source="system")
        try:
            self._health_check(host_port, payload)
        except AgentError:
            logs = _run(
                ["docker", "logs", "--tail", "100", container_name], check=False
            )
            if logs.stdout:
                self._log(logs.stdout, level="error", source="container")
            _run(["docker", "rm", "-f", container_name], check=False)
            raise
        self._write_proxy(str(payload.get("fqdn") or ""), host_port)
        return {
            "container_id": container_id,
            "host_port": host_port,
            "image": image,
            "health": "healthy",
        }

    def _start(self, payload: dict) -> dict:
        container_name = str(payload.get("container_name") or "")
        if not _SAFE_ID_RE.match(container_name):
            raise AgentError("The container name is invalid.")
        exists = _run(["docker", "container", "inspect", container_name], check=False)
        if exists.returncode != 0:
            raise AgentError(
                "The application container no longer exists. Redeploy instead."
            )
        _run(["docker", "start", container_name], timeout=120)
        internal_port = int(payload.get("internal_port") or 8000)
        if payload.get("framework") == "static":
            internal_port = 80
        host_port = self._container_port(container_name, internal_port)
        self._health_check(host_port, payload)
        self._write_proxy(str(payload.get("fqdn") or ""), host_port)
        return {
            "container_id": _run(
                ["docker", "inspect", "-f", "{{.Id}}", container_name]
            ).stdout.strip(),
            "host_port": host_port,
        }

    def _stop(self, payload: dict) -> dict:
        container_name = str(payload.get("container_name") or "")
        if container_name and _SAFE_ID_RE.match(container_name):
            _run(
                ["docker", "stop", "--time", "20", container_name],
                check=False,
                timeout=60,
            )
        self._remove_proxy(str(payload.get("fqdn") or ""))
        return {"stopped": True}

    def _restart(self, payload: dict) -> dict:
        container_name = str(payload.get("container_name") or "")
        if not _SAFE_ID_RE.match(container_name):
            raise AgentError("The container name is invalid.")
        _run(["docker", "restart", "--time", "20", container_name], timeout=120)
        internal_port = int(payload.get("internal_port") or 8000)
        if payload.get("framework") == "static":
            internal_port = 80
        host_port = self._container_port(container_name, internal_port)
        self._health_check(host_port, payload)
        self._write_proxy(str(payload.get("fqdn") or ""), host_port)
        return {"restarted": True, "host_port": host_port}

    def _remove(self, payload: dict) -> dict:
        website_id = str(payload.get("website_id") or "")
        container_name = str(payload.get("container_name") or "")
        if container_name and _SAFE_ID_RE.match(container_name):
            _run(["docker", "rm", "-f", container_name], check=False, timeout=120)
        self._remove_proxy(str(payload.get("fqdn") or ""))
        if _SAFE_ID_RE.match(website_id):
            volume = f"sp-{website_id.replace('-', '')[:24]}-data"
            _run(["docker", "volume", "rm", volume], check=False)
        return {"removed": True}

    def _backup_dir(self) -> Path:
        path = Path(os.getenv("AGENT_BACKUP_DIR", str(self.work_dir / "backups")))
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _backup(self, payload: dict) -> dict:
        website_id = str(payload.get("website_id") or "")
        if not _SAFE_ID_RE.match(website_id):
            raise AgentError("The website identifier is invalid.")
        volume = f"sp-{website_id.replace('-', '')[:24]}-data"
        archive_dir = self._backup_dir() / website_id
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive = archive_dir / (
            f"{website_id}-{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}.tar.gz"
        )
        self._log("Creating a compressed data-volume backup.", source="system")
        _run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{volume}:/data:ro",
                "-v",
                f"{archive_dir}:/backup",
                "alpine:3.20",
                "tar",
                "czf",
                f"/backup/{archive.name}",
                "-C",
                "/data",
                ".",
            ],
            timeout=1800,
        )
        digest = hashlib.sha256()
        with archive.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        size = archive.stat().st_size
        self._log(
            f"Backup created ({size} bytes, sha256 {digest.hexdigest()}).",
            source="system",
        )
        return {
            "backup_path": str(archive),
            "size_bytes": size,
            "checksum_sha256": digest.hexdigest(),
        }

    def _restore(self, payload: dict) -> dict:
        website_id = str(payload.get("website_id") or "")
        if not _SAFE_ID_RE.match(website_id):
            raise AgentError("The website identifier is invalid.")
        archive = Path(str(payload.get("backup_path") or "")).resolve()
        backup_root = self._backup_dir().resolve()
        if not archive.is_relative_to(backup_root) or not archive.is_file():
            raise AgentError(
                "The backup archive is missing or outside the backup directory."
            )
        if archive.suffixes[-2:] != [".tar", ".gz"]:
            raise AgentError("The backup archive must be a .tar.gz file.")
        volume = f"sp-{website_id.replace('-', '')[:24]}-data"
        script = (
            "find /data -mindepth 1 -delete && "
            f"tar xzf /backup/{shlex.quote(archive.name)} -C /data"
        )
        self._log("Restoring the data-volume backup.", source="system")
        _run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{volume}:/data",
                "-v",
                f"{archive.parent}:/backup:ro",
                "alpine:3.20",
                "sh",
                "-c",
                script,
            ],
            timeout=1800,
        )
        return {"restored": True, "backup_path": str(archive)}

    def _collect_logs(self, payload: dict) -> dict:
        container_name = str(payload.get("container_name") or "")
        if not _SAFE_ID_RE.match(container_name):
            raise AgentError("The container name is invalid.")
        result = _run(["docker", "logs", "--tail", "500", container_name], check=False)
        return {
            "logs": ((result.stdout or "") + (result.stderr or ""))[-100000:],
        }


def container_snapshot() -> list[dict]:
    listing = _run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=serverpilot.managed=true",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.State}}",
        ],
        check=False,
        timeout=30,
    )
    if listing.returncode != 0:
        return []
    stats: dict[str, dict] = {}
    stats_result = _run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
        check=False,
        timeout=60,
    )
    if stats_result.returncode == 0:
        for line in (stats_result.stdout or "").splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            stats[str(item.get("ID") or "")[:12]] = item
    containers: list[dict] = []
    for line in (listing.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        docker_id, name, state = parts[0], parts[1], parts[2]
        mapped = {
            "running": "running",
            "created": "created",
            "restarting": "starting",
            "removing": "stopping",
            "paused": "stopped",
            "exited": "exited",
            "dead": "failed",
        }.get(state.lower(), "failed")
        stat = stats.get(docker_id[:12], {})
        containers.append(
            {
                "docker_container_id": docker_id,
                "name": name,
                "status": mapped,
                "cpu_percent": _percent(stat.get("CPUPerc")),
                "ram_mb": _memory_mb(stat.get("MemUsage")),
                "storage_mb": _container_size_mb(docker_id),
            }
        )
    return containers


def _percent(value) -> float:
    try:
        return float(str(value or "0").strip().rstrip("%"))
    except ValueError:
        return 0.0


def _memory_mb(value) -> float:
    try:
        amount = str(value or "").split("/")[0].strip()
        number = float(amount.split()[0])
        unit = amount.split()[1].upper()
    except (IndexError, ValueError):
        return 0.0
    factor = {
        "B": 1 / (1024 * 1024),
        "KIB": 1 / 1024,
        "MIB": 1,
        "GIB": 1024,
        "TIB": 1024 * 1024,
    }.get(unit, 1)
    return round(number * factor, 1)


def _container_size_mb(docker_id: str) -> float:
    result = _run(
        ["docker", "inspect", "--size", "-f", "{{.SizeRw}}", docker_id],
        check=False,
        timeout=20,
    )
    try:
        return round(int(result.stdout.strip()) / (1024 * 1024), 1)
    except (TypeError, ValueError):
        return 0.0


def system_capabilities(work_dir: Path) -> dict:
    import psutil

    usage = shutil.disk_usage(work_dir)
    return {
        "total_ram_mb": max(1, int(psutil.virtual_memory().total / (1024 * 1024))),
        "total_storage_mb": max(1, int(usage.total / (1024 * 1024))),
        "total_cpu_cores": float(psutil.cpu_count(logical=True) or 1),
        "python": "3",
    }


def system_metrics(work_dir: Path) -> dict:
    import psutil

    memory = psutil.virtual_memory()
    usage = shutil.disk_usage(work_dir)
    return {
        "cpu_percent": float(psutil.cpu_percent(interval=0.2)),
        "ram_mb": round((memory.total - memory.available) / (1024 * 1024), 1),
        "storage_mb": round(usage.used / (1024 * 1024), 1),
    }


def docker_available() -> bool:
    return shutil.which("docker") is not None
