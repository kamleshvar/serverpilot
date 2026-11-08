"""Environment-driven configuration for ServerPilot.

All configuration is loaded from environment variables (optionally via ``.env``).
Production fails closed: missing mandatory secrets are fatal. Development may
generate ephemeral secrets so a developer can boot locally, with loud warnings.
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
from datetime import timedelta
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent


def load_environment(env_name: str | None = None) -> str:
    """Load the env file matching the runtime environment.

    Production and staging load their dedicated file (``.env.production`` /
    ``.env.staging``) and never fall back to the development ``.env``. Process
    environment variables always win because ``override`` is disabled.
    """
    name = (env_name or os.getenv("APP_ENV") or "development").strip().lower()
    if name in {"production", "staging"}:
        env_file = BASE_DIR / f".env.{name}"
        if env_file.is_file():
            load_dotenv(env_file, override=False)
    else:
        load_dotenv(BASE_DIR / ".env", override=False)
    return name


LOADED_ENV_NAME = load_environment()

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigurationError(RuntimeError):
    """Raised when configuration is structurally invalid or unsafe to run."""


def env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return default if value is None or value.strip() == "" else value.strip()


def env_bool(name: str, default: bool = False) -> bool:
    raw = env(name)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ConfigurationError(f"{name} must be a boolean value")


def env_int(name: str, default: int) -> int:
    raw = env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc


def env_float(name: str, default: float) -> float:
    raw = env(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc


def clean_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or not _DOMAIN_RE.match(domain):
        raise ConfigurationError(f"Invalid domain name: {value!r}")
    return domain


def load_domains() -> tuple[str, ...]:
    domains: list[str] = []
    for index in (1, 2, 3):
        raw = env(f"DOMAIN_{index}")
        if raw:
            domains.append(clean_domain(raw))
    if len(set(domains)) != len(domains):
        raise ConfigurationError("DOMAIN_1..DOMAIN_3 must be unique")
    return tuple(domains)


def load_encryption_keys(raw: str | None) -> list[str]:
    if not raw:
        return []
    keys = [part.strip() for part in raw.split(",") if part.strip()]
    for key in keys:
        try:
            Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as exc:  # pragma: no cover - message is the contract
            raise ConfigurationError(
                "ENCRYPTION_KEY must be a Fernet key. Generate one with: "
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            ) from exc
    return keys


def normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def strict_database_uri() -> str | None:
    """Return the configured database URI without a SQLite fallback."""
    raw = env("DATABASE_URL")
    return normalize_database_url(raw) if raw else None


def _oauth_redirect(provider: str) -> str:
    explicit = env(f"{provider}_REDIRECT_URI")
    if explicit:
        return explicit
    return f"{env('APP_URL', 'http://localhost:5000')}/auth/{provider.lower()}/callback"


def _trusted_proxies() -> tuple[str, ...]:
    raw = env("TRUSTED_PROXIES", "")
    result: list[str] = []
    if raw:
        for item in raw.split(","):
            value = item.strip()
            if value:
                ipaddress.ip_network(value, strict=False)
                result.append(value)
    return tuple(result)


def _parse_networks(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    result: list[str] = []
    for item in raw.split(","):
        value = item.strip()
        if value:
            ipaddress.ip_network(value, strict=False)
            result.append(value)
    return tuple(result)


def _parse_int_list(raw: str | None) -> tuple[int, ...]:
    if not raw:
        return ()
    values: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            values.append(int(item))
    return tuple(values)


class BaseConfig:
    APP_NAME = env("APP_NAME", "ServerPilot")
    ENV_NAME = "base"
    VERSION = "0.1.0-stage1"
    DEBUG = False

    APP_URL = env("APP_URL", "http://localhost:5000").rstrip("/")
    SECRET_KEY = env("SECRET_KEY")
    ENCRYPTION_KEY = env("ENCRYPTION_KEY")
    ENCRYPTION_KEYS: ClassVar[list[str]] = []

    SQLALCHEMY_DATABASE_URI = normalize_database_url(
        env("DATABASE_URL", "sqlite:///serverpilot-dev.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict] = {"pool_pre_ping": True}

    PREFERRED_URL_SCHEME = "https" if APP_URL.startswith("https://") else "http"
    SESSION_COOKIE_NAME = "serverpilot_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = APP_URL.startswith("https://")
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = APP_URL.startswith("https://")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=env_int("SESSION_LIFETIME_HOURS", 24))
    SESSION_REFRESH_EACH_REQUEST = True
    ADMIN_SESSION_LIFETIME = timedelta(
        minutes=env_int("ADMIN_SESSION_LIFETIME_MINUTES", 60)
    )
    ADMIN_DEPLOYMENT_AUTH_LIFETIME = timedelta(
        minutes=env_int("ADMIN_DEPLOYMENT_AUTH_MINUTES", 20)
    )
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = APP_URL.startswith("https://")
    WTF_CSRF_HEADERS: ClassVar[list[str]] = ["X-CSRFToken", "X-CSRF-Token"]

    FORCE_HTTPS = env_bool("FORCE_HTTPS", APP_URL.startswith("https://"))
    TRUSTED_PROXY_COUNT = env_int("TRUSTED_PROXY_COUNT", 1)
    TRUSTED_PROXIES = _trusted_proxies()

    DOMAINS = load_domains()
    USER_ALLOWED_DOMAIN = env("USER_ALLOWED_DOMAIN") or (DOMAINS[0] if DOMAINS else "")
    if USER_ALLOWED_DOMAIN:
        USER_ALLOWED_DOMAIN = clean_domain(USER_ALLOWED_DOMAIN)
    ADMIN_PANEL_PATH = "/techorigin"

    GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = _oauth_redirect("GOOGLE")
    GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

    GITHUB_CLIENT_ID = env("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = env("GITHUB_CLIENT_SECRET")
    GITHUB_REDIRECT_URI = _oauth_redirect("GITHUB")
    GITHUB_OAUTH_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)

    GITHUB_APP_ID = env("GITHUB_APP_ID")
    GITHUB_APP_CLIENT_ID = env("GITHUB_APP_CLIENT_ID")
    GITHUB_APP_CLIENT_SECRET = env("GITHUB_APP_CLIENT_SECRET")
    GITHUB_APP_PRIVATE_KEY = env("GITHUB_APP_PRIVATE_KEY", "")
    GITHUB_APP_PRIVATE_KEY_PATH = env("GITHUB_APP_PRIVATE_KEY_PATH")
    GITHUB_APP_WEBHOOK_SECRET = env("GITHUB_APP_WEBHOOK_SECRET")
    GITHUB_APP_SLUG = env("GITHUB_APP_SLUG")
    GITHUB_WEBHOOK_URL = env("GITHUB_WEBHOOK_URL", f"{APP_URL}/webhooks/github")
    GITHUB_APP_SETUP_URL = env("GITHUB_APP_SETUP_URL")
    GITHUB_APP_ENABLED = bool(
        GITHUB_APP_ID and (GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH)
    )

    CLOUDFLARE_API_TOKEN = env("CLOUDFLARE_API_TOKEN")
    CLOUDFLARE_ACCOUNT_ID = env("CLOUDFLARE_ACCOUNT_ID")
    CLOUDFLARE_TUNNEL_ID = env("CLOUDFLARE_TUNNEL_ID")
    CLOUDFLARE_TUNNEL_CNAME = env("CLOUDFLARE_TUNNEL_CNAME")
    CLOUDFLARE_DNS_TTL = env_int("CLOUDFLARE_DNS_TTL", 1)
    CLOUDFLARE_PROXIED = env_bool("CLOUDFLARE_PROXIED", True)
    CLOUDFLARE_ENABLED = bool(CLOUDFLARE_API_TOKEN)

    ADMIN_PASSWORD_HASH = env("ADMIN_PASSWORD_HASH")
    ADMIN_EMAIL = env("ADMIN_EMAIL")
    ADMIN_GITHUB_ID = env("ADMIN_GITHUB_ID")
    ADMIN_DEPLOYMENT_AUTH_REQUIRED = env_bool("ADMIN_DEPLOYMENT_AUTH_REQUIRED", True)
    ADMIN_EMAIL_VERIFICATION_REQUIRED = env_bool(
        "ADMIN_EMAIL_VERIFICATION_REQUIRED", True
    )

    AGENT_SIGNING_SECRET = env("AGENT_SIGNING_SECRET")
    AGENT_BOOTSTRAP_TOKEN = env("AGENT_BOOTSTRAP_TOKEN")
    AGENT_CONTROL_PLANE_URL = env(
        "AGENT_CONTROL_PLANE_URL", env("APP_URL", "http://localhost:5000")
    ).rstrip("/")
    AGENT_ENROLLMENT_TTL_SECONDS = env_int("AGENT_ENROLLMENT_TTL_SECONDS", 900)
    AGENT_INSTALL_DIR = env("AGENT_INSTALL_DIR", "/opt/serverpilot-agent")
    AGENT_CONFIG_DIR = env("AGENT_CONFIG_DIR", "/etc/serverpilot")
    AGENT_SERVICE_USER = env("AGENT_SERVICE_USER", "serverpilot")
    AGENT_HEARTBEAT_INTERVAL = env_int("AGENT_HEARTBEAT_INTERVAL", 30)
    AGENT_TASK_TIMEOUT = env_int("AGENT_TASK_TIMEOUT", 1800)
    AGENT_OFFLINE_AFTER_SECONDS = env_int("AGENT_OFFLINE_AFTER_SECONDS", 120)
    AGENT_POLL_INTERVAL = env_int("AGENT_POLL_INTERVAL", 5)
    AGENT_INSTALL_WAIT_SECONDS = env_int("AGENT_INSTALL_WAIT_SECONDS", 60)

    SSH_CONNECT_TIMEOUT = env_int("SSH_CONNECT_TIMEOUT", 15)
    SSH_COMMAND_TIMEOUT = env_int("SSH_COMMAND_TIMEOUT", 30)
    SSH_SCAN_TIMEOUT = env_int("SSH_SCAN_TIMEOUT", 60)
    SSH_MAX_OUTPUT_BYTES = env_int("SSH_MAX_OUTPUT_BYTES", 2_000_000)
    SSH_KNOWN_HOSTS_PATH = env("SSH_KNOWN_HOSTS_PATH")
    SSH_REQUIRE_HOST_KEY_FINGERPRINT = env_bool(
        "SSH_REQUIRE_HOST_KEY_FINGERPRINT", True
    )
    SSH_ALLOW_PRIVATE_TARGETS = env_bool("SSH_ALLOW_PRIVATE_TARGETS", False)
    SSH_ALLOWED_NETWORKS = _parse_networks(env("SSH_ALLOWED_NETWORKS"))

    REDIS_URL = env("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL = env("CELERY_BROKER_URL", "redis://localhost:6379/1")
    CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
    CELERY_TASK_ALWAYS_EAGER = False
    CELERY_TASK_EAGER_PROPAGATES = True
    CELERY_TASK_TIME_LIMIT = env_int("DEPLOYMENT_TIMEOUT", 900)
    CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

    RATELIMIT_STORAGE_URI = env("RATELIMIT_STORAGE_URI") or "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    OAUTH_LOGIN_RATE_LIMIT = env("OAUTH_LOGIN_RATE_LIMIT", "20 per minute")
    ADMIN_LOGIN_RATE_LIMIT = env("ADMIN_LOGIN_RATE_LIMIT", "5 per minute")
    SERVER_PROVISION_RATE_LIMIT = env("SERVER_PROVISION_RATE_LIMIT", "5 per minute")

    DEPLOYMENT_TIMEOUT = env_int("DEPLOYMENT_TIMEOUT", 900)
    BUILD_TIMEOUT = env_int("BUILD_TIMEOUT", 600)
    DOCKER_SOCKET_PATH = env("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
    AGENT_WORK_DIR = env("AGENT_WORK_DIR", "/var/lib/serverpilot")
    AGENT_PROXY_DIR = env("AGENT_PROXY_DIR", "/etc/nginx/conf.d/serverpilot")
    AGENT_DOCKER_NETWORK = env("AGENT_DOCKER_NETWORK", "serverpilot-apps")

    DEFAULT_MAX_WEBSITES = max(1, min(10, env_int("DEFAULT_MAX_WEBSITES", 5)))
    MAX_ADMIN_WEBSITES = max(
        DEFAULT_MAX_WEBSITES, min(10, env_int("MAX_ADMIN_WEBSITES", 10))
    )
    DEFAULT_RAM_LIMIT_MB = env_int("DEFAULT_RAM_LIMIT_MB", 2048)
    DEFAULT_STORAGE_LIMIT_GB = env_int("DEFAULT_STORAGE_LIMIT_GB", 10)
    DEFAULT_STORAGE_LIMIT_MB = DEFAULT_STORAGE_LIMIT_GB * 1024
    DEFAULT_WEBSITE_RAM_MB = env_int("DEFAULT_WEBSITE_RAM_MB", 512)
    DEFAULT_WEBSITE_CPU = env_float("DEFAULT_WEBSITE_CPU", 0.5)
    DEFAULT_WEBSITE_STORAGE_MB = env_int("DEFAULT_WEBSITE_STORAGE_MB", 2048)

    MONITORING_INTERVAL_SECONDS = env_int("MONITORING_INTERVAL_SECONDS", 30)
    QUOTA_ENFORCEMENT_INTERVAL_SECONDS = env_int(
        "QUOTA_ENFORCEMENT_INTERVAL_SECONDS", 60
    )
    SERVER_CPU_ALERT_PERCENT = env_int("SERVER_CPU_ALERT_PERCENT", 90)
    SERVER_RAM_ALERT_PERCENT = env_int("SERVER_RAM_ALERT_PERCENT", 90)
    SERVER_DISK_ALERT_PERCENT = env_int("SERVER_DISK_ALERT_PERCENT", 90)
    SERVER_MONITORING_HISTORY_LIMIT = env_int("SERVER_MONITORING_HISTORY_LIMIT", 60)
    SUSPENSION_STOP_WEBSITES = env_bool("SUSPENSION_STOP_WEBSITES", True)

    BACKUP_DIRECTORY = env("BACKUP_DIRECTORY", str(BASE_DIR / "instance" / "backups"))
    BACKUP_RETENTION_DAYS = env_int("BACKUP_RETENTION_DAYS", 7)
    DATABASE_BACKUP_RETENTION_DAYS = env_int("DATABASE_BACKUP_RETENTION_DAYS", 14)
    BACKUP_ENCRYPTION_ENABLED = env_bool("BACKUP_ENCRYPTION_ENABLED", True)

    SMTP_HOST = env("SMTP_HOST")
    SMTP_PORT = env_int("SMTP_PORT", 587)
    SMTP_USERNAME = env("SMTP_USERNAME")
    SMTP_PASSWORD = env("SMTP_PASSWORD")
    SMTP_FROM_EMAIL = env("SMTP_FROM_EMAIL")
    SMTP_USE_TLS = env_bool("SMTP_USE_TLS", True)
    MAIL_SERVER = SMTP_HOST
    MAIL_PORT = SMTP_PORT
    MAIL_USERNAME = SMTP_USERNAME
    MAIL_PASSWORD = SMTP_PASSWORD
    MAIL_USE_TLS = SMTP_USE_TLS
    MAIL_DEFAULT_SENDER = SMTP_FROM_EMAIL
    MAIL_SUPPRESS_SEND = not bool(SMTP_HOST)

    LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()
    LOG_DIR = env("LOG_DIR", str(BASE_DIR / "instance" / "logs"))
    LOG_JSON = env_bool("LOG_JSON", False)
    LOG_MAX_BYTES = 10 * 1024 * 1024
    LOG_BACKUP_COUNT = 10

    INSTANCE_DIR = str(BASE_DIR / "instance")
    ARTIFACTS_DIR = str(BASE_DIR / "instance" / "artifacts")
    UPLOAD_DIR = str(BASE_DIR / "instance" / "uploads")
    SOCKETIO_MESSAGE_QUEUE = None
    SOCKETIO_ASYNC_MODE = "threading"
    SOCKETIO_CORS_ALLOWED_ORIGINS: ClassVar[list[str]] = [APP_URL]
    TESTING = False

    @classmethod
    def validate(cls, app) -> tuple[list[str], list[str]]:
        """Return (errors, warnings). Production errors are fatal."""
        errors: list[str] = []
        warnings: list[str] = []
        strict = app.config["ENV_NAME"] in {"production", "staging"}

        if not app.config.get("SECRET_KEY"):
            (errors if strict else warnings).append("SECRET_KEY is not set")
        elif len(app.config["SECRET_KEY"]) < 32:
            (errors if strict else warnings).append(
                "SECRET_KEY must be at least 32 characters"
            )

        if not app.config.get("ENCRYPTION_KEY"):
            (errors if strict else warnings).append(
                "ENCRYPTION_KEY is not set; encrypted integration tokens will not survive restarts"
            )
        else:
            load_encryption_keys(app.config["ENCRYPTION_KEY"])

        domains = app.config.get("DOMAINS", ())
        if not domains:
            errors.append("At least DOMAIN_1 must be configured")
        if len(domains) > 3:
            errors.append("At most three domains (DOMAIN_1..3) are supported")
        user_domain = app.config.get("USER_ALLOWED_DOMAIN")
        if user_domain and user_domain not in domains:
            errors.append("USER_ALLOWED_DOMAIN must be one of DOMAIN_1..DOMAIN_3")
        if strict and len(domains) < 3:
            warnings.append(
                "Fewer than three domains configured; admin domain selector will expose only configured domains"
            )

        app_url = app.config.get("APP_URL", "")
        parsed = urlparse(app_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            errors.append("APP_URL must be an absolute http(s) URL")
        if strict and parsed.scheme != "https":
            errors.append("APP_URL must use https in production")

        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
        if not db_uri:
            errors.append("DATABASE_URL is required")
        elif strict and not db_uri.startswith("postgresql://"):
            errors.append(
                "DATABASE_URL must be a PostgreSQL URL in production/staging (SQLite fallback is disabled)"
            )

        if strict and not app.config.get("FORCE_HTTPS"):
            errors.append("FORCE_HTTPS must be enabled in production")
        if strict and not (
            app.config.get("SESSION_COOKIE_SECURE")
            and app.config.get("REMEMBER_COOKIE_SECURE")
        ):
            errors.append(
                "Secure session and remember cookies must be enabled in production"
            )

        admin_hash = app.config.get("ADMIN_PASSWORD_HASH")
        if admin_hash and ":" not in admin_hash:
            errors.append("ADMIN_PASSWORD_HASH is not a Werkzeug password hash")
        if strict and not admin_hash:
            errors.append("ADMIN_PASSWORD_HASH is required in production")
        if strict and not app.config.get("ADMIN_EMAIL"):
            errors.append("ADMIN_EMAIL is required in production")
        if not admin_hash:
            warnings.append(
                "Admin password login disabled: ADMIN_PASSWORD_HASH is missing"
            )
        if not app.config.get("ADMIN_EMAIL"):
            warnings.append(
                "ADMIN_EMAIL is missing: admin DB identity cannot be provisioned"
            )

        if app.config.get("ADMIN_DEPLOYMENT_AUTH_REQUIRED") and not (
            app.config.get("ADMIN_GITHUB_ID") or app.config.get("ADMIN_EMAIL")
        ):
            warnings.append(
                "Admin deployment authorization is enabled but no authorized GitHub ID or email is configured"
            )

        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            warnings.append("Google OAuth disabled: GOOGLE_CLIENT_ID/SECRET missing")
        if not app.config.get("GITHUB_OAUTH_ENABLED"):
            warnings.append("GitHub OAuth disabled: GITHUB_CLIENT_ID/SECRET missing")
        if not app.config.get("GITHUB_APP_ENABLED"):
            warnings.append("GitHub App disabled: app ID/private key missing")
        if not app.config.get("CLOUDFLARE_ENABLED"):
            warnings.append(
                "Cloudflare integration disabled: CLOUDFLARE_API_TOKEN missing"
            )
        elif not (
            app.config.get("CLOUDFLARE_TUNNEL_CNAME")
            or app.config.get("CLOUDFLARE_TUNNEL_ID")
        ):
            warnings.append(
                "Cloudflare DNS is enabled but no tunnel target is configured; "
                "set CLOUDFLARE_TUNNEL_CNAME or CLOUDFLARE_TUNNEL_ID"
            )
        if strict and not app.config.get("AGENT_SIGNING_SECRET"):
            errors.append("AGENT_SIGNING_SECRET is required in production")
        if strict and not app.config.get("REDIS_URL"):
            warnings.append(
                "REDIS_URL is missing; realtime/background features require Redis"
            )

        if strict and app.config.get("SOCKETIO_ASYNC_MODE") == "threading":
            warnings.append(
                "SocketIO threading mode is intended for development; use Redis-backed workers in production"
            )

        if app.config.get("DEFAULT_MAX_WEBSITES", 0) > app.config.get(
            "MAX_ADMIN_WEBSITES", 10
        ):
            errors.append("DEFAULT_MAX_WEBSITES cannot exceed MAX_ADMIN_WEBSITES")
        if not (1 <= app.config.get("DEFAULT_MAX_WEBSITES", 0) <= 10):
            errors.append("DEFAULT_MAX_WEBSITES must be between 1 and 10")

        return errors, warnings


class DevelopmentConfig(BaseConfig):
    ENV_NAME = "development"
    DEBUG = env_bool("FLASK_DEBUG", False)
    RATELIMIT_STORAGE_URI = env("RATELIMIT_STORAGE_URI") or "memory://"


class TestingConfig(BaseConfig):
    ENV_NAME = "testing"
    TESTING = True
    DEBUG = False
    SECRET_KEY = "test-secret-key-with-at-least-32-characters"
    ENCRYPTION_KEYS: ClassVar[list[str]] = []
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict] = {}
    WTF_CSRF_ENABLED = False
    FORCE_HTTPS = False
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    MAIL_SUPPRESS_SEND = True
    MAIL_SERVER = None
    LOG_LEVEL = "WARNING"
    DOMAINS = ("techorigin.online", "example.org", "example.net")
    USER_ALLOWED_DOMAIN = "techorigin.online"
    ADMIN_EMAIL = "admin@example.com"
    ADMIN_GITHUB_ID = "123456"
    ADMIN_PASSWORD_HASH = None
    ADMIN_DEPLOYMENT_AUTH_REQUIRED = False
    AGENT_SIGNING_SECRET = "test-agent-signing-secret-with-at-least-32-characters"
    AGENT_BOOTSTRAP_TOKEN = "test-agent-bootstrap-token"
    AGENT_HEARTBEAT_INTERVAL = 30
    AGENT_POLL_INTERVAL = 1
    AGENT_TASK_TIMEOUT = 1800
    AGENT_OFFLINE_AFTER_SECONDS = 120
    AGENT_CONTROL_PLANE_URL = "https://panel.test"
    AGENT_INSTALL_WAIT_SECONDS = 1
    SSH_ALLOW_PRIVATE_TARGETS = True
    SSH_REQUIRE_HOST_KEY_FINGERPRINT = False
    GOOGLE_OAUTH_ENABLED = False
    GITHUB_OAUTH_ENABLED = False
    GITHUB_APP_ENABLED = False
    CLOUDFLARE_ENABLED = False
    TESTING_DOMAIN = "techorigin.online"


class StagingConfig(BaseConfig):
    ENV_NAME = "staging"
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = strict_database_uri()


class ProductionConfig(BaseConfig):
    ENV_NAME = "production"
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = strict_database_uri()
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"
    FORCE_HTTPS = True
    SOCKETIO_MESSAGE_QUEUE = env("REDIS_URL", "redis://localhost:6379/0")
    RATELIMIT_STORAGE_URI = env("RATELIMIT_STORAGE_URI") or env(
        "REDIS_URL", "redis://localhost:6379/0"
    )


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "staging": StagingConfig,
    "production": ProductionConfig,
}


def get_config(env_name: str | None = None):
    name = (env_name or os.getenv("APP_ENV") or "development").strip().lower()
    if name not in CONFIG_MAP:
        raise ConfigurationError(
            f"Unknown APP_ENV={name!r}; expected one of {sorted(CONFIG_MAP)}"
        )
    return CONFIG_MAP[name]


def generate_dev_secrets() -> tuple[str, str]:
    return secrets.token_hex(32), Fernet.generate_key().decode()
