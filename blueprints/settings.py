"""User connections: OAuth identities and GitHub App installations."""

from __future__ import annotations

import logging

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from ..decorators import active_user_required
from ..errors import (
    ConflictError,
    IntegrationNotConfigured,
    PermissionDenied,
    ValidationError,
)
from ..extensions import db, limiter
from ..models import (
    GithubInstallation,
    GithubInstallationStatus,
    Website,
    WebsiteStatus,
)
from ..services.github_app import (
    GithubAppError,
    app_install_url,
    github_app_configured,
    link_installation,
    list_repositories,
    oauth_repositories_for,
    sync_installation,
    user_installations,
)

logger = logging.getLogger(__name__)

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.get("/connections")
@active_user_required
def connections():
    installations = user_installations(current_user)
    return render_template(
        "settings/connections.html",
        identities=current_user.identities,
        installations=installations,
        github_app_configured=github_app_configured(),
        install_url=app_install_url(),
        github_app_slug=current_app.config.get("GITHUB_APP_SLUG"),
    )


@bp.get("/github/setup")
@active_user_required
@limiter.limit("10 per minute")
def github_setup():
    setup_action = (request.args.get("setup_action") or "").strip()
    raw_id = request.args.get("installation_id")
    if not raw_id:
        flash("GitHub did not return an installation identifier.", "error")
        return redirect(url_for("settings.connections"))
    try:
        installation_id = int(raw_id)
    except ValueError:
        flash("The GitHub installation identifier is invalid.", "error")
        return redirect(url_for("settings.connections"))

    if setup_action == "deleted":
        existing = GithubInstallation.query.filter_by(
            installation_id=installation_id, user_id=current_user.id
        ).one_or_none()
        if existing is not None:
            existing.status = GithubInstallationStatus.DELETED
            db.session.commit()
            flash("GitHub App installation disconnected.", "info")
        return redirect(url_for("settings.connections"))

    try:
        installation = link_installation(current_user, installation_id)
    except (GithubAppError, PermissionDenied, ConflictError, ValidationError) as exc:
        logger.warning(
            "GitHub installation link failed user=%s installation=%s reason=%s",
            current_user.email,
            installation_id,
            type(exc).__name__,
        )
        flash(str(exc), "error")
        return redirect(url_for("settings.connections"))

    flash(
        f"GitHub App installed for {installation.account_login}. You can now "
        "select repositories when creating a website.",
        "success",
    )
    return redirect(url_for("settings.connections"))


@bp.post("/github/installations/<installation_id>/disconnect")
@active_user_required
def disconnect_installation(installation_id: str):
    installation = GithubInstallation.query.filter_by(
        id=installation_id, user_id=current_user.id
    ).one_or_none()
    if installation is None:
        flash("GitHub installation not found.", "error")
        return redirect(url_for("settings.connections"))
    in_use = Website.query.filter(
        Website.github_installation_id == installation.id,
        Website.status != WebsiteStatus.DELETED,
    ).count()
    if in_use:
        flash(
            "This installation is still used by websites. Delete those websites "
            "before disconnecting it.",
            "error",
        )
        return redirect(url_for("settings.connections"))
    installation.status = GithubInstallationStatus.DELETED
    db.session.commit()
    flash("GitHub App installation disconnected.", "info")
    return redirect(url_for("settings.connections"))


@bp.post("/github/installations/<installation_id>/sync")
@active_user_required
def sync_github_installation(installation_id: str):
    installation = GithubInstallation.query.filter_by(
        id=installation_id, user_id=current_user.id
    ).one_or_none()
    if installation is None:
        flash("GitHub installation not found.", "error")
        return redirect(url_for("settings.connections"))
    try:
        sync_installation(installation)
    except GithubAppError as exc:
        flash(str(exc), "error")
    else:
        flash("GitHub installation synchronized.", "success")
    return redirect(url_for("settings.connections"))


@bp.get("/github/repositories")
@active_user_required
@limiter.limit("20 per minute")
def repositories_api():
    try:
        repositories = list_repositories(current_user)
    except IntegrationNotConfigured:
        repositories = oauth_repositories_for(current_user)
    return jsonify(
        {
            "repositories": [
                {
                    "full_name": repo.full_name,
                    "default_branch": repo.default_branch,
                    "private": repo.private,
                }
                for repo in repositories
            ]
        }
    )
