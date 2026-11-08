"""Request hardening: proxy trust, HTTPS, request IDs and response headers."""

from __future__ import annotations

import re
import uuid

from flask import Flask, g, redirect, request
from werkzeug.middleware.proxy_fix import ProxyFix

from .logging_config import request_id_var

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_SENSITIVE_PREFIXES = (
    "/techorigin",
    "/dashboard",
    "/websites",
    "/deployments",
    "/domains",
    "/resources",
    "/logs",
    "/backups",
    "/notifications",
    "/settings",
    "/api/",
)


def init_security(app: Flask) -> None:
    proxy_count = int(app.config.get("TRUSTED_PROXY_COUNT", 0) or 0)
    if proxy_count > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
            x_port=proxy_count,
            x_prefix=proxy_count,
        )

    @app.before_request
    def enforce_https_and_request_id():
        request_id = request.headers.get("X-Request-ID", "")
        if not _REQUEST_ID_RE.match(request_id):
            request_id = uuid.uuid4().hex
        g.request_id = request_id
        request_id_var.set(request_id)

        if (
            app.config.get("FORCE_HTTPS")
            and not app.config.get("TESTING")
            and not request.is_secure
            and request.path != "/healthz"
            and request.headers.get("X-Forwarded-Proto") != "https"
        ):
            if request.method in {"GET", "HEAD"}:
                return redirect(request.url.replace("http://", "https://", 1), 308)
            return (
                "HTTPS required",
                400,
                {"Content-Type": "text/plain; charset=utf-8"},
            )
        return None

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Request-ID", g.get("request_id", "-"))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Server", "ServerPilot")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' ws: wss:;",
        )
        if app.config.get("FORCE_HTTPS") and not app.config.get("TESTING"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )
        if any(request.path.startswith(prefix) for prefix in _SENSITIVE_PREFIXES):
            response.headers.setdefault("Cache-Control", "no-store, private")
        return response
