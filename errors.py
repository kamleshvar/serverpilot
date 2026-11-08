"""Typed application errors and consistent HTML/JSON error handling."""

from __future__ import annotations

import logging
import uuid

from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

from .extensions import db
from .logging_config import request_id_var

logger = logging.getLogger(__name__)


class AppError(Exception):
    status_code = 400
    code = "bad_request"
    default_message = "The request could not be processed."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict | None = None,
        status_code: int | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message or self.default_message)
        self.message = message or self.default_message
        self.details = details or {}
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code

    def to_dict(self) -> dict:
        payload = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        payload["request_id"] = request_id_var.get()
        return payload


class ValidationError(AppError):
    status_code = 422
    code = "validation_error"
    default_message = "Some submitted values are invalid."


class AuthenticationRequired(AppError):
    status_code = 401
    code = "authentication_required"
    default_message = "Please sign in to continue."


class PermissionDenied(AppError):
    status_code = 403
    code = "permission_denied"
    default_message = "You do not have permission to perform this action."


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"
    default_message = "The requested resource was not found."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    default_message = "The request conflicts with the current state."


class QuotaExceededError(AppError):
    status_code = 409
    code = "quota_exceeded"
    default_message = "Your plan quota has been reached."


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"
    default_message = "Too many requests. Please try again later."


class IntegrationNotConfigured(AppError):
    status_code = 503
    code = "integration_not_configured"
    default_message = (
        "This integration is not configured. An administrator must add its "
        "credentials in the backend environment."
    )


class AgentUnavailable(AppError):
    status_code = 503
    code = "agent_unavailable"
    default_message = "No healthy deployment agent is available."


class InternalError(AppError):
    status_code = 500
    code = "internal_error"
    default_message = "An unexpected error occurred. Please try again."


def wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    best = request.accept_mimetypes.best
    return bool(best == "application/json" and request.accept_mimetypes[best] > 0)


def _error_response(error: AppError, status: int):
    if wants_json():
        return jsonify({"error": error.to_dict()}), status
    try:
        rendered = render_template(
            "errors/error.html",
            status_code=status,
            error_code=error.code,
            message=error.message,
        )
    except Exception:  # noqa: BLE001 - template may not exist during bootstrap
        rendered = f"{status} — {error.message}"
    return rendered, status


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(AppError)
    def handle_app_error(error: AppError):
        if error.status_code >= 500:
            logger.exception("Application error: %s", error.message)
        else:
            logger.info(
                "Request rejected: code=%s status=%s message=%s",
                error.code,
                error.status_code,
                error.message,
            )
        return _error_response(error, error.status_code)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error: CSRFError):
        app.logger.warning("CSRF validation failed: %s", error.description)
        return _error_response(
            AppError(
                "Your session form token is missing or expired. Refresh the page "
                "and try again.",
                code="csrf_failed",
                status_code=400,
            ),
            400,
        )

    @app.errorhandler(429)
    def handle_rate_limit(error: HTTPException):
        return _error_response(
            RateLimitedError("Too many requests. Please wait a moment and try again."),
            429,
        )

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        mapping = {
            400: ("bad_request", "The request is invalid."),
            401: ("authentication_required", "Please sign in to continue."),
            403: ("permission_denied", "You do not have permission for this action."),
            404: ("not_found", "The requested page or resource was not found."),
            405: ("method_not_allowed", "This action is not allowed here."),
            413: ("payload_too_large", "The uploaded content is too large."),
            429: ("rate_limited", "Too many requests."),
        }
        code, message = mapping.get(
            error.code or 500,
            ("http_error", error.description or "Request failed."),
        )
        app_error = AppError(message, code=code, status_code=error.code or 500)
        return _error_response(app_error, error.code or 500)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        request_id = request_id_var.get() or str(uuid.uuid4())
        logger.exception(
            "Unhandled exception request_id=%s path=%s", request_id, request.path
        )
        try:
            db.session.rollback()
        except Exception:
            logger.exception("Failed to roll back database session")
        if app.config.get("TESTING"):
            raise error
        return _error_response(
            InternalError(
                "An unexpected error occurred. If it persists, contact support "
                f"and include request ID {request_id}."
            ),
            500,
        )
