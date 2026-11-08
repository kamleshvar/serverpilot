"""Typed platform settings stored in the database."""

from __future__ import annotations

from typing import Any

from flask import current_app

from ..extensions import db
from ..models import PlatformSetting, User

DEFAULTS: dict[str, Any] = {
    "allow_new_deployments": True,
    "suspension_stop_websites": True,
    "backup_retention_days": 7,
    "deployment_artifact_retention_days": 30,
    "default_maintenance_message": "This website is temporarily unavailable for maintenance.",
    "platform_maintenance_message": "",
    "cloudflare_tunnel_target": "",
    "dns_required_records": [],
    "notify_admins_on_server_alerts": True,
    "deployment_requires_admin_approval": False,
}

_MISSING = object()


def seed_default_settings(*, commit: bool = True) -> None:
    existing = {
        setting.key
        for setting in PlatformSetting.query.filter(
            PlatformSetting.key.in_(list(DEFAULTS))
        ).all()
    }
    for key, value in DEFAULTS.items():
        if key not in existing:
            db.session.add(
                PlatformSetting(key=key, value=value, description=key.replace("_", " "))
            )
    if commit:
        db.session.commit()


def get_setting(key: str, default: Any = _MISSING) -> Any:
    setting = PlatformSetting.query.filter_by(key=key).one_or_none()
    if setting is not None:
        return setting.value
    if default is not _MISSING:
        return default
    if key in DEFAULTS:
        return DEFAULTS[key]
    raise KeyError(f"Unknown platform setting {key!r}")


def get_int_setting(key: str, default: int) -> int:
    value = get_setting(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_bool_setting(key: str, default: bool) -> bool:
    value = get_setting(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def set_setting(
    key: str,
    value: Any,
    *,
    updated_by: User | None = None,
    commit: bool = True,
) -> PlatformSetting:
    setting = PlatformSetting.query.filter_by(key=key).one_or_none()
    if setting is None:
        setting = PlatformSetting(key=key, description=key.replace("_", " "))
        db.session.add(setting)
    setting.value = value
    setting.updated_by_id = updated_by.id if updated_by else None
    if commit:
        db.session.commit()
    return setting


def public_runtime_settings() -> dict[str, Any]:
    return {
        "app_name": current_app.config["APP_NAME"],
        "environment": current_app.config["ENV_NAME"],
        "domain": current_app.config.get("USER_ALLOWED_DOMAIN"),
        "deployments_enabled": get_bool_setting("allow_new_deployments", True),
    }
