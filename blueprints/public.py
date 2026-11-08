"""Public pages, health probes and version metadata."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, url_for
from sqlalchemy import text

from ..extensions import db
from ..utils import utcnow

bp = Blueprint("public", __name__)


@bp.get("/")
def index():
    return render_template("public/landing.html")


@bp.get("/healthz")
def healthz():
    checks: dict[str, str] = {}
    healthy = True
    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001 - health checks must report any failure
        db.session.rollback()
        checks["database"] = "error"
        healthy = False
    payload = {
        "status": "ok" if healthy else "degraded",
        "service": current_app.config["APP_NAME"],
        "version": current_app.config["VERSION"],
        "environment": current_app.config["ENV_NAME"],
        "timestamp": utcnow().isoformat(),
        "checks": checks,
    }
    return jsonify(payload), (200 if healthy else 503)


@bp.get("/readyz")
def readyz():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ready"}), 200
    except Exception:  # noqa: BLE001 - readiness probes must report any failure
        db.session.rollback()
        return jsonify({"status": "not_ready"}), 503


@bp.get("/robots.txt")
def robots():
    body = (
        "User-agent: *\nDisallow: /techorigin\nDisallow: /dashboard\nDisallow: /api/\n"
    )
    return current_app.response_class(body, mimetype="text/plain")


@bp.get("/api/v1")
def api_root():
    return jsonify(
        {
            "service": "ServerPilot API",
            "version": "v1",
            "health": url_for("public.healthz", _external=True),
            "documentation": "/docs/api",
        }
    )
