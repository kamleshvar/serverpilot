"""Secure, administrator-only SSH transport and Ubuntu server discovery.

No private key, passphrase or sudo credential is persisted by this module.
Commands are fixed server-side operations; no request value is ever executed as
a shell command.
"""

from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import re
import select
import socket
import time
from dataclasses import dataclass
from typing import Any, Self

import paramiko
from flask import current_app

from ..errors import AppError, ValidationError
from ..utils import utcnow

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")
_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}")
_SAFE_PATH_RE = re.compile(r"^/tmp/serverpilot-agent-[a-f0-9]{16,64}$")


class SSHConnectionError(AppError):
    status_code = 502
    code = "ssh_connection_failed"
    default_message = "The SSH connection could not be established."


class SSHScanError(AppError):
    status_code = 502
    code = "ssh_scan_failed"
    default_message = "The remote server scan failed."


@dataclass(frozen=True)
class SSHCredentials:
    host: str
    port: int
    username: str
    private_key: str
    passphrase: str | None = None
    host_key_fingerprint: str | None = None


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_status: int


class _FingerprintPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str) -> None:
        self.expected = expected

    def missing_host_key(self, client, hostname, key) -> None:
        actual = fingerprint_key(key)
        if not _fingerprint_equal(actual, self.expected):
            raise paramiko.SSHException(
                "The SSH host key fingerprint does not match the expected fingerprint."
            )


def fingerprint_key(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def normalize_fingerprint(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.upper().startswith("MD5:"):
        raise ValidationError(
            "Use the SHA256 SSH host key fingerprint (SHA256:...). MD5 fingerprints are not accepted."
        )
    if not raw.upper().startswith("SHA256:"):
        raw = "SHA256:" + raw
    if raw.endswith("="):
        raw = raw.rstrip("=")
    if not _FINGERPRINT_RE.match(raw):
        raise ValidationError("The SSH host key fingerprint is invalid.")
    return raw


def _fingerprint_equal(left: str, right: str) -> bool:
    return left.rstrip("=") == right.rstrip("=")


def validate_target(host: str, port: int) -> tuple[str, str, list[str]]:
    """Validate an SSH target and resolve it without permitting unsafe SSRF targets."""
    raw = (host or "").strip().lower().rstrip(".")
    if not raw or not _HOST_RE.match(raw) or "\x00" in raw:
        raise ValidationError("Enter a valid server IP address or hostname.")
    if not (1 <= int(port) <= 65535):
        raise ValidationError("SSH port must be between 1 and 65535.")

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(raw, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValidationError("The server address could not be resolved.") from exc
    if not addresses:
        raise ValidationError("The server address did not resolve to an address.")

    allowed = tuple(
        ipaddress.ip_network(value, strict=False)
        for value in current_app.config.get("SSH_ALLOWED_NETWORKS", ())
    )
    allow_private = bool(current_app.config.get("SSH_ALLOW_PRIVATE_TARGETS", False))
    checked: list[str] = []
    for raw_ip in sorted(addresses):
        try:
            address = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        except ValueError as exc:
            raise ValidationError(
                "The server address resolved to an invalid IP address."
            ) from exc
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ValidationError(
                "Loopback, link-local and multicast SSH targets are not allowed."
            )
        if allowed and not any(address in network for network in allowed):
            raise ValidationError("The SSH target is outside SSH_ALLOWED_NETWORKS.")
        if not allowed and not address.is_global and not allow_private:
            raise ValidationError(
                "Private SSH targets are disabled. Enable SSH_ALLOW_PRIVATE_TARGETS or "
                "set SSH_ALLOWED_NETWORKS for approved internal networks."
            )
        if not allowed and address.is_reserved:
            raise ValidationError("Reserved SSH target addresses are not allowed.")
        checked.append(str(address))
    return raw, checked[0], checked


def _load_private_key(credentials: SSHCredentials) -> paramiko.PKey:
    material = credentials.private_key or ""
    if "PRIVATE KEY" not in material:
        raise ValidationError("Enter an SSH private key in PEM/OpenSSH format.")
    password = credentials.passphrase or None
    password_required = False
    for key_class in (
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
    ):
        try:
            return key_class.from_private_key(io.StringIO(material), password=password)
        except paramiko.PasswordRequiredException:
            password_required = True
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    if password_required:
        raise ValidationError("The SSH private key is encrypted; enter its passphrase.")
    raise ValidationError(
        "The SSH private key could not be read. Use an unencrypted or passphrase-protected key."
    )


class SSHSession:
    def __init__(
        self,
        client: paramiko.SSHClient,
        sock: socket.socket,
        host: str,
        fingerprint: str,
        address: str = "",
    ):
        self.client = client
        self._sock = sock
        self.host = host
        self.fingerprint = fingerprint
        self.address = address

    def close(self) -> None:
        try:
            self.client.close()
        finally:
            try:
                self._sock.close()
            except OSError:
                pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def run(
        self,
        command: str,
        *,
        timeout: int | None = None,
        stdin_text: str | None = None,
    ) -> CommandResult:
        timeout = int(timeout or current_app.config.get("SSH_COMMAND_TIMEOUT", 30))
        limit = int(current_app.config.get("SSH_MAX_OUTPUT_BYTES", 2_000_000))
        channel = None
        try:
            stdin, _stdout, _stderr = self.client.exec_command(command, timeout=timeout)
            channel = stdin.channel
            if stdin_text is not None:
                stdin.write(stdin_text)
                stdin.flush()
            stdin.channel.shutdown_write()
            out = bytearray()
            err = bytearray()
            deadline = time.monotonic() + max(1, timeout)
            while True:
                while channel.recv_ready():
                    out.extend(channel.recv(65536))
                    if len(out) > limit:
                        raise SSHScanError(
                            "The SSH command returned more output than the configured limit."
                        )
                while channel.recv_stderr_ready():
                    err.extend(channel.recv_stderr(65536))
                    if len(err) > limit:
                        raise SSHScanError(
                            "The SSH command returned more output than the configured limit."
                        )
                if (
                    channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                ):
                    break
                if time.monotonic() >= deadline:
                    raise SSHConnectionError(
                        "The SSH command did not complete in time."
                    )
                select.select([channel], [], [], 0.1)
            code = channel.recv_exit_status()
        except SSHScanError:
            raise
        except SSHConnectionError:
            raise
        except (TimeoutError, paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(
                "The SSH command did not complete in time."
            ) from exc
        finally:
            if channel is not None:
                channel.close()
        return CommandResult(
            stdout=bytes(out).decode("utf-8", errors="replace").replace("\x00", ""),
            stderr=bytes(err).decode("utf-8", errors="replace").replace("\x00", ""),
            exit_status=code,
        )

    def upload(self, data: bytes, remote_path: str) -> None:
        directory, _, filename = remote_path.rpartition("/")
        if not _SAFE_PATH_RE.match(directory) or not re.match(
            r"^[A-Za-z0-9_.-]{1,128}$", filename
        ):
            raise ValidationError("The install upload path is invalid.")
        try:
            with self.client.open_sftp() as sftp:
                with sftp.file(remote_path, "wb") as handle:
                    handle.write(data)
                sftp.chmod(remote_path, 0o600)
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError("The agent bundle could not be uploaded.") from exc

    def cleanup(self, remote_dir: str) -> None:
        if not _SAFE_PATH_RE.match(remote_dir):
            return
        try:
            self.run(f"rm -rf -- {remote_dir}", timeout=15)
        except AppError:
            pass


def connect(credentials: SSHCredentials) -> SSHSession:
    host, address, _addresses = validate_target(credentials.host, credentials.port)
    username = (credentials.username or "").strip()
    if not re.match(r"^[a-z_][a-z0-9_.-]{0,31}$", username):
        raise ValidationError("The SSH username is invalid.")

    expected = normalize_fingerprint(credentials.host_key_fingerprint)
    known_hosts_path = current_app.config.get("SSH_KNOWN_HOSTS_PATH")
    require_fingerprint = bool(
        current_app.config.get("SSH_REQUIRE_HOST_KEY_FINGERPRINT", True)
    )
    has_known_hosts = bool(known_hosts_path)
    if require_fingerprint and not expected and not has_known_hosts:
        raise ValidationError(
            "SSH host key verification requires a SHA256 fingerprint or SSH_KNOWN_HOSTS_PATH."
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    if has_known_hosts:
        try:
            client.load_host_keys(str(known_hosts_path))
        except OSError as exc:
            raise ValidationError("SSH_KNOWN_HOSTS_PATH could not be read.") from exc
    if expected:
        client.set_missing_host_key_policy(_FingerprintPolicy(expected))

    pkey = _load_private_key(credentials)
    sock = None
    try:
        sock = socket.create_connection(
            (address, credentials.port),
            timeout=int(current_app.config.get("SSH_CONNECT_TIMEOUT", 15)),
        )
        client.connect(
            hostname=host,
            port=credentials.port,
            username=username,
            pkey=pkey,
            sock=sock,
            timeout=int(current_app.config.get("SSH_CONNECT_TIMEOUT", 15)),
            banner_timeout=int(current_app.config.get("SSH_CONNECT_TIMEOUT", 15)),
            auth_timeout=int(current_app.config.get("SSH_CONNECT_TIMEOUT", 15)),
            allow_agent=False,
            look_for_keys=False,
        )
        transport = client.get_transport()
        if transport is None:
            raise SSHConnectionError("The SSH transport did not initialize.")
        transport.set_keepalive(30)
        actual = fingerprint_key(transport.get_remote_server_key())
        if expected and not _fingerprint_equal(actual, expected):
            raise SSHConnectionError("The SSH host key fingerprint does not match.")
        return SSHSession(client, sock, host, actual, address)
    except paramiko.AuthenticationException as exc:
        client.close()
        if sock is not None:
            sock.close()
        raise SSHConnectionError(
            "SSH authentication failed. Check the username and private key."
        ) from exc
    except paramiko.BadHostKeyException as exc:
        client.close()
        if sock is not None:
            sock.close()
        raise SSHConnectionError(
            "The SSH host key changed and does not match known_hosts."
        ) from exc
    except paramiko.SSHException as exc:
        client.close()
        if sock is not None:
            sock.close()
        raise SSHConnectionError(f"SSH negotiation failed: {exc}") from exc
    except (TimeoutError, OSError) as exc:
        client.close()
        if sock is not None:
            sock.close()
        raise SSHConnectionError(
            "The server is unreachable or the SSH port is closed."
        ) from exc


_ALLOWED_SCAN_COMMANDS = {
    "os_release": "cat /etc/os-release",
    "kernel": "uname -r",
    "hostname": "hostname",
    "uptime": "uptime -p",
    "cpu": "lscpu",
    "memory": "free -m",
    "disk": "df -P -B1 /",
    "docker_version": "docker --version",
    "docker_active": "systemctl is-active docker",
    "docker_ps": "docker ps --format '{{json .}}'",
    "nginx_version": "nginx -v",
    "nginx_active": "systemctl is-active nginx",
    "python": "python3 --version",
    "git": "git --version",
    "gunicorn": "command -v gunicorn && gunicorn --version",
    "addresses": "ip -o -4 addr show",
    "route": "ip route get 1.1.1.1",
    "public_ip": "curl -4 -fsS --max-time 5 https://api.ipify.org",
    "listening": "ss -lntH",
    "nginx_files": "find /etc/nginx/sites-enabled /etc/nginx/conf.d -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | head -n 50",
    "nginx_names": "grep -RhE '^[[:space:]]*server_name' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | head -n 100",
    "hosting_dirs": "find /var/www /srv /opt -maxdepth 2 -mindepth 1 -type d 2>/dev/null | head -n 100",
    "services": "systemctl is-active docker nginx apache2 mysql postgresql redis-server 2>/dev/null",
}


def _first_version(text: str) -> str | None:
    match = _VERSION_RE.search(text or "")
    return match.group(0) if match else None


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            values[key.strip()] = value.strip().strip('"').strip("'")
        except ValueError:
            continue
    return values


def _parse_lscpu(text: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return {
        "model": values.get("Model name") or values.get("Model name:"),
        "architecture": values.get("Architecture"),
        "cores": values.get("CPU(s)") or values.get("Core(s) per socket"),
    }


def _parse_memory(text: str) -> dict[str, float]:
    values: dict[str, float] = {}
    keys = {
        "Mem",
        "MemFree",
        "MemAvailable",
        "Buffers",
        "Cached",
        "Swap",
        "SwapFree",
    }
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].rstrip(":") in keys:
            try:
                values[parts[0].rstrip(":")] = float(parts[1])
            except ValueError:
                continue
    return values


def _parse_disk(text: str) -> dict[str, Any]:
    lines = [line for line in (text or "").splitlines() if line.strip()]
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            try:
                total = int(parts[1])
                used = int(parts[2])
                available = int(parts[3])
            except ValueError:
                continue
            return {
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available,
                "percent": round((used / total) * 100, 1) if total else 0.0,
                "mount": parts[5],
            }
    return {}


def _parse_interfaces(text: str) -> list[dict[str, str]]:
    interfaces: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        match = re.match(r"^\d+:\s+([^:]+):.*\sinet\s+([^\s]+)", line)
        if match:
            interfaces.append(
                {"name": match.group(1).strip(), "address": match.group(2)}
            )
    return interfaces


def _parse_ports(text: str) -> list[int]:
    ports: set[int] = set()
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        try:
            port = int(local.rsplit(":", 1)[-1])
        except ValueError:
            continue
        if 8 <= port <= 65535:
            ports.add(port)
    return sorted(ports)


def _parse_containers(text: str) -> list[dict[str, str]]:
    containers: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            containers.append(
                {
                    "name": str(item.get("Names") or item.get("Name") or "")[:120],
                    "image": str(item.get("Image") or "")[:255],
                    "state": str(item.get("State") or "")[:32],
                    "status": str(item.get("Status") or "")[:120],
                    "ports": str(item.get("Ports") or "")[:500],
                }
            )
    return containers[:500]


def _parse_nginx_names(text: str) -> list[str]:
    names: set[str] = set()
    for line in (text or "").splitlines():
        if "server_name" not in line:
            continue
        body = line.split("server_name", 1)[1].replace(";", " ")
        for token in body.split():
            token = token.strip().lower().rstrip(".")
            if (
                token
                and token not in {"_", "localhost"}
                and re.match(r"^[a-z0-9.*-]+$", token)
            ):
                names.add(token[:253])
    return sorted(names)[:100]


def _capture(
    session: SSHSession,
    results: dict[str, Any],
    warnings: list[str],
    errors: list[str],
    key: str,
    command: str,
    *,
    label: str,
    required_for: str | None = None,
) -> CommandResult:
    try:
        result = session.run(
            command, timeout=int(current_app.config.get("SSH_SCAN_TIMEOUT", 60))
        )
    except AppError as exc:
        if required_for:
            errors.append(f"{required_for}: {exc.message}")
        else:
            warnings.append(f"{label} could not be collected: {exc.message}")
        return CommandResult("", "", 255)
    if result.exit_status != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        summary = detail[0][:240] if detail else f"exit status {result.exit_status}"
        warnings.append(f"{label}: {summary}")
    results[key] = {
        "exit_status": result.exit_status,
        "stdout": result.stdout[:20000],
        "stderr": result.stderr[:4000],
    }
    return result


def scan_server(session: SSHSession) -> dict[str, Any]:
    results: dict[str, Any] = {"collected_at": utcnow().isoformat(), "commands": {}}
    warnings: list[str] = []
    errors: list[str] = []
    raw = results["commands"]
    captured: dict[str, CommandResult] = {}
    required = {
        "os_release": "Operating system information",
        "hostname": "Hostname",
        "cpu": "CPU information",
        "memory": "Memory information",
        "disk": "Disk information",
    }
    for key, command in _ALLOWED_SCAN_COMMANDS.items():
        if (
            command not in _ALLOWED_SCAN_COMMANDS.values()
        ):  # defensive: fixed commands only
            raise SSHScanError("An unapproved scan command was requested.")
        captured[key] = _capture(
            session,
            raw,
            warnings,
            errors,
            key,
            command,
            label=key.replace("_", " "),
            required_for=required.get(key),
        )

    os_info = _parse_os_release(captured["os_release"].stdout)
    lscpu = _parse_lscpu(captured["cpu"].stdout)
    memory = _parse_memory(captured["memory"].stdout)
    disk = _parse_disk(captured["disk"].stdout)
    total_ram_mb = int(memory.get("Mem", 0))
    free_ram_mb = int(memory.get("MemFree", 0))
    available_ram_mb = int(memory.get("MemAvailable", 0) or free_ram_mb)
    ram_usage = (
        round(((total_ram_mb - available_ram_mb) / total_ram_mb) * 100, 1)
        if total_ram_mb
        else 0.0
    )
    docker_version = _first_version(
        captured["docker_version"].stdout + captured["docker_version"].stderr
    )
    nginx_version = _first_version(
        captured["nginx_version"].stdout + captured["nginx_version"].stderr
    )
    docker_active = captured["docker_active"].stdout.strip().lower()
    nginx_active = captured["nginx_active"].stdout.strip().lower()
    python_version = _first_version(
        captured["python"].stdout + captured["python"].stderr
    )
    git_version = _first_version(captured["git"].stdout + captured["git"].stderr)
    gunicorn_version = _first_version(
        captured["gunicorn"].stdout + captured["gunicorn"].stderr
    )
    public_ip = (captured["public_ip"].stdout or "").strip().splitlines()
    route = captured["route"].stdout
    route_ip = None
    try:
        route_ip = route.split("src", 1)[1].split()[0]
    except (IndexError, AttributeError):
        pass
    services: dict[str, str] = {}
    names = ["docker", "nginx", "apache2", "mysql", "postgresql", "redis-server"]
    for name, value in zip(
        names, captured["services"].stdout.splitlines(), strict=False
    ):
        services[name] = value.strip() or "unknown"
    containers = _parse_containers(captured["docker_ps"].stdout)
    nginx_files = [
        line.strip()
        for line in captured["nginx_files"].stdout.splitlines()
        if line.strip()
    ][:50]
    hosting_dirs = [
        line.strip()
        for line in captured["hosting_dirs"].stdout.splitlines()
        if line.strip()
    ][:100]

    if not docker_version:
        warnings.append("Docker is not installed.")
    elif docker_active != "active":
        warnings.append("Docker is installed but the docker service is not active.")
    if not nginx_version:
        warnings.append("Nginx is not installed.")
    elif nginx_active != "active":
        warnings.append("Nginx is installed but the nginx service is not active.")
    if not python_version:
        warnings.append("Python 3 is not installed.")
    if not git_version:
        warnings.append("Git is not installed.")
    if not gunicorn_version:
        warnings.append("Gunicorn is not installed.")
    if not os_info.get("NAME"):
        errors.append("Operating system information could not be parsed.")
    if not total_ram_mb:
        errors.append("Memory information could not be parsed.")
    if not disk:
        errors.append("Disk information could not be parsed.")

    results.update(
        {
            "hostname": (captured["hostname"].stdout or "")
            .strip()
            .splitlines()[0][:253]
            if captured["hostname"].stdout.strip()
            else None,
            "operating_system": {
                "name": os_info.get("NAME"),
                "version": os_info.get("VERSION") or os_info.get("VERSION_ID"),
                "pretty_name": os_info.get("PRETTY_NAME"),
                "id": os_info.get("ID"),
            },
            "hardware": {
                "cpu_model": lscpu.get("model"),
                "architecture": lscpu.get("architecture"),
                "cpu_cores": lscpu.get("cores"),
                "total_ram_mb": total_ram_mb,
                "free_ram_mb": free_ram_mb,
                "available_ram_mb": available_ram_mb,
                "ram_usage_percent": ram_usage,
                "disk": disk,
            },
            "software": {
                "docker": {
                    "status": "running"
                    if docker_active == "active"
                    else ("installed" if docker_version else "not_installed"),
                    "version": docker_version,
                },
                "nginx": {
                    "status": "running"
                    if nginx_active == "active"
                    else ("installed" if nginx_version else "not_installed"),
                    "version": nginx_version,
                },
                "python": {
                    "status": "installed" if python_version else "not_installed",
                    "version": python_version,
                },
                "git": {
                    "status": "installed" if git_version else "not_installed",
                    "version": git_version,
                },
                "gunicorn": {
                    "status": "installed" if gunicorn_version else "not_installed",
                    "version": gunicorn_version,
                },
                "services": services,
                "containers": containers,
            },
            "network": {
                "interfaces": _parse_interfaces(captured["addresses"].stdout),
                "route_source_ip": route_ip,
                "public_ip": public_ip[0][:45]
                if public_ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", public_ip[0].strip())
                else None,
                "listening_ports": _parse_ports(captured["listening"].stdout),
            },
            "hosting": {
                "nginx_files": nginx_files,
                "nginx_server_names": _parse_nginx_names(
                    captured["nginx_names"].stdout
                ),
                "directories": hosting_dirs,
            },
        }
    )
    results["warnings"] = warnings
    results["errors"] = errors
    return results


def apply_scan_to_server(server, scan_results: dict[str, Any]) -> None:
    os_info = scan_results.get("operating_system") or {}
    hardware = scan_results.get("hardware") or {}
    software = scan_results.get("software") or {}
    disk = hardware.get("disk") or {}
    docker = software.get("docker") or {}
    nginx = software.get("nginx") or {}
    server.operating_system = (os_info.get("pretty_name") or os_info.get("name") or "")[
        :120
    ] or None
    server.os_version = (os_info.get("version") or "")[:120] or None
    server.cpu_model = (hardware.get("cpu_model") or "")[:255] or None
    if hardware.get("cpu_cores"):
        try:
            server.total_cpu_cores = max(
                1.0, float(str(hardware["cpu_cores"]).split()[0])
            )
        except (TypeError, ValueError):
            pass
    if hardware.get("total_ram_mb"):
        server.total_ram_mb = max(1, int(hardware["total_ram_mb"]))
    if disk.get("total_bytes"):
        server.total_storage_mb = max(1, int(disk["total_bytes"] / (1024 * 1024)))
    server.docker_status = str(docker.get("status") or "unknown")[:32]
    server.docker_version = str(docker.get("version") or "")[:64] or None
    server.nginx_status = str(nginx.get("status") or "unknown")[:32]
    server.nginx_version = str(nginx.get("version") or "")[:64] or None
    kernel = (scan_results.get("commands") or {}).get("kernel") or {}
    kernel_version = str(kernel.get("stdout") or "").strip().splitlines()
    if kernel_version:
        server.kernel_version = kernel_version[0][:120]
    server.last_scan_at = utcnow()


def remote_preflight(
    session: SSHSession, *, sudo_password: str | None = None
) -> dict[str, Any]:
    commands = {
        "python": "python3 --version",
        "venv": "python3 -c 'import venv'",
        "docker": "docker --version",
        "docker_active": "systemctl is-active docker",
        "nginx": "nginx -t",
        "systemd": "systemctl --version",
        "sudo": "sudo --version",
        "curl": "command -v curl",
    }
    output: dict[str, Any] = {}
    failures: list[str] = []
    for key, command in commands.items():
        result = session.run(command, timeout=30)
        if key == "nginx" and result.exit_status != 0:
            if sudo_password:
                result = session.run(
                    "sudo -S -p '' nginx -t",
                    timeout=30,
                    stdin_text=sudo_password + "\n",
                )
            else:
                result = session.run("sudo -n nginx -t", timeout=30)
        output[key] = {
            "exit_status": result.exit_status,
            "stdout": result.stdout[:2000],
            "stderr": result.stderr[:1000],
        }
        if result.exit_status != 0:
            failures.append(key)
    if "python" in failures or "venv" in failures:
        raise ValidationError("Python 3 with venv support is required on the server.")
    if "docker" in failures:
        raise ValidationError(
            "Docker must be installed before the agent can be installed."
        )
    if "docker_active" in failures:
        raise ValidationError(
            "Docker must be running before the agent can be installed."
        )
    if "nginx" in failures:
        raise ValidationError(
            "Nginx must be installed and its configuration valid before the agent can be installed."
        )
    if "systemd" in failures:
        raise ValidationError("systemd is required to run the agent service.")
    if "sudo" in failures:
        raise ValidationError(
            "sudo is required for the restricted Nginx reload permission. Install sudo "
            "or run the installer with a dedicated sudo policy."
        )
    return output


def install_command_script(
    remote_dir: str, sudo_password: str | None = None
) -> tuple[str, str | None]:
    if not _SAFE_PATH_RE.match(remote_dir):
        raise ValidationError("The agent install path is invalid.")
    if sudo_password:
        command = f"sudo -S -p '' /bin/bash {remote_dir}/install.sh"
        return command, sudo_password + "\n"
    return f"sudo -n /bin/bash {remote_dir}/install.sh", None
