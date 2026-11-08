"""ServerPilot application factory."""

from __future__ import annotations

import time
from pathlib import Path

from cryptography.fernet import Fernet
from flask import Flask, g, jsonify, redirect, request, url_for
from flask_login import current_user

from .config import (
    CONFIG_MAP,
    ConfigurationError,
    get_config,
    load_encryption_keys,
)
from .errors import AuthenticationRequired, register_error_handlers
from .extensions import (
    csrf,
    db,
    limiter,
    login_manager,
    mail,
    migrate,
    socketio,
)
from .logging_config import configure_logging
from .security import init_security
from .services.encryption import init_encryption
from .services.oauth import init_oauth
from .utils import format_duration, humanize_bytes, utcnow


def _finalize_secrets(app: Flask) -> None:
    strict = app.config["ENV_NAME"] in {"production", "staging"}
    ephemeral: list[str] = []

    if not app.config.get("SECRET_KEY"):
        if strict:
            return
        app.config["SECRET_KEY"] = Fernet.generate_key().decode()
        ephemeral.append("SECRET_KEY")

    raw_key = app.config.get("ENCRYPTION_KEY")
    keys = load_encryption_keys(raw_key)
    if not keys:
        if strict:
            return
        generated = Fernet.generate_key().decode()
        keys = [generated]
        app.config["ENCRYPTION_KEY"] = generated
        ephemeral.append("ENCRYPTION_KEY")
    app.config["ENCRYPTION_KEYS"] = keys
    app.config["EPHEMERAL_SECRETS"] = ephemeral


def _validate_configuration(app: Flask) -> None:
    config_class = CONFIG_MAP[app.config["ENV_NAME"]]
    errors, warnings = config_class.validate(app)
    app.config["CONFIG_WARNINGS"] = warnings
    for warning in warnings:
        app.logger.warning("Configuration: %s", warning)
    if errors:
        raise ConfigurationError(
            "Invalid ServerPilot configuration:\n- " + "\n- ".join(errors)
        )


def _ensure_directories(app: Flask) -> None:
    paths = [
        app.instance_path,
        app.config["LOG_DIR"],
        app.config["ARTIFACTS_DIR"],
        app.config["UPLOAD_DIR"],
        app.config["BACKUP_DIRECTORY"],
    ]
    for raw in paths:
        try:
            Path(raw).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError(
                f"Unable to create required directory {raw!r}: {exc}"
            ) from exc


def _configure_login(app: Flask) -> None:
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id: str):
        from .models import User

        user = db.session.get(User, user_id)
        if user is None or not user.is_active:
            return None
        return user

    @login_manager.unauthorized_handler
    def unauthorized():
        if (
            request.path.startswith("/api/")
            or request.accept_mimetypes.best == "application/json"
        ):
            error = AuthenticationRequired()
            return jsonify({"error": error.to_dict()}), 401
        from flask import flash

        flash("Please sign in to continue.", "warning")
        return redirect(url_for("auth.login", next=request.full_path))


def _register_blueprints(app: Flask) -> None:
    from .blueprints.admin import bp as admin_bp
    from .blueprints.admin_servers import bp as admin_servers_bp
    from .blueprints.agent_api import bp as agent_api_bp
    from .blueprints.auth import bp as auth_bp
    from .blueprints.dashboard import bp as dashboard_bp
    from .blueprints.public import bp as public_bp
    from .blueprints.settings import bp as settings_bp
    from .blueprints.sites import bp as sites_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(sites_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_servers_bp)
    app.register_blueprint(agent_api_bp)


def _register_template_helpers(app: Flask) -> None:
    @app.context_processor
    def inject_globals():
        from .services.settings import public_runtime_settings

        try:
            runtime = public_runtime_settings()
        except Exception:  # noqa: BLE001 - fall back to static template settings
            runtime = {
                "app_name": app.config["APP_NAME"],
                "environment": app.config["ENV_NAME"],
                "domain": app.config.get("USER_ALLOWED_DOMAIN"),
                "deployments_enabled": False,
            }
        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["VERSION"],
            "app_environment": app.config["ENV_NAME"],
            "runtime_settings": runtime,
            "plan_limits": {
                "max_websites": app.config["DEFAULT_MAX_WEBSITES"],
                "ram_limit_mb": app.config["DEFAULT_RAM_LIMIT_MB"],
                "storage_limit_gb": app.config["DEFAULT_STORAGE_LIMIT_GB"],
            },
            "current_year": utcnow().year,
            "google_oauth_enabled": app.config.get("GOOGLE_OAUTH_ENABLED", False),
            "github_oauth_enabled": app.config.get("GITHUB_OAUTH_ENABLED", False),
            "github_app_enabled": app.config.get("GITHUB_APP_ENABLED", False),
            "cloudflare_enabled": app.config.get("CLOUDFLARE_ENABLED", False),
            "current_user": current_user,
        }

    app.jinja_env.filters["human_bytes"] = humanize_bytes
    app.jinja_env.filters["duration"] = format_duration
    app.jinja_env.globals["config_warnings"] = app.config.get("CONFIG_WARNINGS", [])


def _register_request_metrics(app: Flask) -> None:
    @app.before_request
    def start_timer():
        g.request_started_at = time.perf_counter()

    @app.after_request
    def log_request(response):
        if app.config.get("TESTING"):
            return response
        started = getattr(g, "request_started_at", None)
        elapsed_ms = (time.perf_counter() - started) * 1000 if started else 0
        if not request.path.startswith("/static/"):
            app.logger.info(
                "%s %s -> %s (%.1fms)",
                request.method,
                request.path,
                response.status_code,
                elapsed_ms,
            )
        return response


def create_app(
    config_name: str | None = None, config_overrides: dict | None = None
) -> Flask:
    config_class = get_config(config_name)
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    if config_overrides:
        app.config.update(config_overrides)

    _ensure_directories(app)
    configure_logging(app)
    _finalize_secrets(app)
    _validate_configuration(app)

    app.json.sort_keys = False
    app.config.setdefault("SESSION_COOKIE_PATH", "/")

    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        options = dict(app.config.get("SQLALCHEMY_ENGINE_OPTIONS") or {})
        connect_args = dict(options.get("connect_args") or {})
        connect_args.setdefault("check_same_thread", False)
        options["connect_args"] = connect_args
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = options

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    _configure_login(app)
    init_encryption(app)
    init_oauth(app)

    socketio.init_app(
        app,
        async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "threading"),
        message_queue=app.config.get("SOCKETIO_MESSAGE_QUEUE"),
        cors_allowed_origins=app.config.get("SOCKETIO_CORS_ALLOWED_ORIGINS", []),
        logger=False,
        engineio_logger=False,
    )

    init_security(app)
    register_error_handlers(app)
    _register_blueprints(app)
    _register_template_helpers(app)
    _register_request_metrics(app)

    from . import models  # noqa: F401  (register model metadata)
    from .cli import register_cli

    register_cli(app)

    @app.teardown_request
    def reset_request_id(_exc):
        from .logging_config import request_id_var

        request_id_var.set("-")

    app.extensions["serverpilot_started_at"] = utcnow()
    app.logger.info(
        "%s %s started in %s mode",
        app.config["APP_NAME"],
        app.config["VERSION"],
        app.config["ENV_NAME"],
    )
    return app
