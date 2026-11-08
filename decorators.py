"""Reusable authorization decorators (never trust the frontend)."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from flask import flash, g, redirect, request, url_for
from flask_login import current_user

from .errors import AppError, PermissionDenied, wants_json
from .services.admin_auth import (
    admin_deployment_authorized,
    admin_session_user,
)
from .utils import safe_next_url


def _wants_api_response() -> bool:
    return wants_json()


def active_user_required(view: Callable):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_active:
            if _wants_api_response():
                raise AppError(
                    "Sign in is required.",
                    code="authentication_required",
                    status_code=401,
                )
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=safe_next_url()))
        g.user = current_user
        return view(*args, **kwargs)

    return wrapper


def admin_required(view: Callable):
    @wraps(view)
    def wrapper(*args, **kwargs):
        admin = admin_session_user()
        if admin is None:
            if _wants_api_response():
                raise AppError(
                    "Administrator authentication is required.",
                    code="admin_authentication_required",
                    status_code=401,
                )
            flash("Administrator authentication is required.", "warning")
            target = (
                request.full_path
                if request.method == "GET"
                else url_for("admin.dashboard")
            )
            return redirect(url_for("admin.login", next=target))
        g.admin_user = admin
        return view(*args, **kwargs)

    return wrapper


def admin_deployment_required(view: Callable):
    @wraps(view)
    def wrapper(*args, **kwargs):
        admin = admin_session_user()
        if admin is None:
            if _wants_api_response():
                raise AppError(
                    "Administrator authentication is required.",
                    code="admin_authentication_required",
                    status_code=401,
                )
            flash("Administrator authentication is required.", "warning")
            return redirect(url_for("admin.login", next=url_for("admin.dashboard")))
        g.admin_user = admin
        if not admin_deployment_authorized():
            if _wants_api_response():
                error = PermissionDenied(
                    "Confirm your administrator deployment identity before "
                    "performing deployment actions.",
                    code="admin_deployment_auth_required",
                    details={
                        "authorize_url": url_for(
                            "admin.deployment_auth", _external=True
                        )
                    },
                )
                from flask import jsonify

                return jsonify({"error": error.to_dict()}), error.status_code
            flash(
                "Confirm your authorized GitHub or verified email identity "
                "before performing deployment actions.",
                "warning",
            )
            return redirect(url_for("admin.deployment_auth"))
        return view(*args, **kwargs)

    return wrapper
