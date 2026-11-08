"""Ownership-scoped website configuration routes."""

from __future__ import annotations

import logging

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user

from ..decorators import active_user_required
from ..errors import AppError, IntegrationNotConfigured, NotFoundError, PermissionDenied
from ..forms import WebsiteForm
from ..models import Deployment, Framework
from ..services.backups import (
    create_website_backup,
    list_website_backups,
    request_restore,
)
from ..services.deployments import create_deployment, request_start, request_stop
from ..services.domains import (
    all_managed_domains,
    get_user_allowed_domain,
)
from ..services.github_app import (
    app_install_url,
    github_app_configured,
    oauth_repositories_for,
    user_installations,
    verify_repository,
    verify_repository_user_token,
)
from ..services.quota import quota_snapshot
from ..services.websites import (
    EDITABLE_STATUSES,
    WebsiteInput,
    create_website,
    delete_website,
    owned_website,
    update_website,
)

logger = logging.getLogger(__name__)

bp = Blueprint("sites", __name__, url_prefix="/sites")


def _domain_choices():
    if current_user.is_admin:
        domains = all_managed_domains()
    else:
        domains = [get_user_allowed_domain()]
    return [(domain.name, domain.name) for domain in domains]


def _prepare_form(form: WebsiteForm) -> None:
    form.domain_name.choices = _domain_choices()


def _payload_from_form(form: WebsiteForm) -> WebsiteInput:
    return WebsiteInput(
        name=form.name.data or "",
        subdomain=form.subdomain.data or "",
        domain_name=form.domain_name.data or "",
        repository_full_name=(form.repository_full_name.data or "").strip(),
        branch=(form.branch.data or "main").strip(),
        framework=Framework(form.framework.data),
        build_command=form.build_command.data,
        start_command=form.start_command.data,
        root_directory=form.root_directory.data or "",
        internal_port=int(form.internal_port.data or 8000),
        healthcheck_path=form.healthcheck_path.data or "/",
        auto_deploy_enabled=bool(form.auto_deploy_enabled.data),
    )


def _github_identity_present() -> bool:
    return any(
        identity.provider.value == "github" for identity in current_user.identities
    )


def _auto_repositories() -> tuple[list[str], str | None]:
    """Auto-load repository names for the linked GitHub account (OAuth app)."""
    try:
        repos = oauth_repositories_for(current_user)
    except AppError as exc:
        return [], exc.message
    return [repo.full_name for repo in repos], None


def _render_new(form: WebsiteForm, *, status: int = 200):
    app_configured = github_app_configured()
    installations = user_installations(current_user) if app_configured else []
    has_github_identity = _github_identity_present()
    repositories: list[str] = []
    repository_error: str | None = None
    if (not app_configured or not installations) and has_github_identity:
        repositories, repository_error = _auto_repositories()
    return (
        render_template(
            "sites/new.html",
            form=form,
            installations=installations,
            github_app_configured=app_configured,
            has_github_identity=has_github_identity,
            install_url=app_install_url(),
            repositories=repositories,
            repository_error=repository_error,
        ),
        status,
    )


@bp.get("/new")
@active_user_required
def new():
    form = WebsiteForm()
    _prepare_form(form)
    domains = _domain_choices()
    if domains and not form.domain_name.data:
        form.domain_name.data = domains[0][0]
    form.framework.data = form.framework.data or Framework.FLASK.value
    return _render_new(form)


@bp.post("/new")
@active_user_required
def create():
    form = WebsiteForm()
    _prepare_form(form)
    if not form.validate_on_submit():
        return _render_new(form, status=422)

    installation = None
    repository = None
    if github_app_configured():
        try:
            installation, repository = verify_repository(
                current_user, form.repository_full_name.data or ""
            )
        except AppError as exc:
            flash(exc.message, "error")
            return _render_new(form, status=exc.status_code)
    else:
        # GitHub App not configured: verify access through the linked
        # GitHub account's OAuth authorization instead.
        try:
            repository = verify_repository_user_token(
                current_user, form.repository_full_name.data or ""
            )
        except PermissionDenied as exc:
            flash(exc.message, "error")
            return _render_new(form, status=exc.status_code)
        except (IntegrationNotConfigured, AppError) as exc:
            flash(exc.message, "error")
            return _render_new(form, status=exc.status_code)

    try:
        payload = _payload_from_form(form)
        payload.repository_full_name = repository.full_name
        if not (form.branch.data or "").strip():
            payload.branch = repository.default_branch
        website = create_website(
            current_user,
            payload,
            github_installation=installation,
            repository_default_branch=repository.default_branch,
        )
    except AppError as exc:
        flash(exc.message, "error")
        return _render_new(form, status=exc.status_code)

    try:
        deployment = create_deployment(current_user, website)
    except AppError as exc:
        flash(
            f"Website {website.fqdn} created. {exc.message}",
            "success",
        )
        return redirect(url_for("sites.detail", website_id=website.id))
    return redirect(
        url_for(
            "sites.deployment_detail",
            website_id=website.id,
            deployment_id=deployment.id,
        )
    )


@bp.get("/<website_id>")
@active_user_required
def detail(website_id: str):
    website = owned_website(current_user, website_id)
    deployments = website.deployments[:10] if website.deployments else []
    return render_template(
        "sites/detail.html",
        website=website,
        deployments=deployments,
        quota=quota_snapshot(current_user),
        agent_available=_agent_available(),
        can_edit=website.status in EDITABLE_STATUSES,
        backups=list_website_backups(website),
    )


@bp.get("/<website_id>/deployments/<deployment_id>")
@active_user_required
def deployment_detail(website_id: str, deployment_id: str):
    website = owned_website(current_user, website_id)
    deployment = Deployment.query.filter_by(
        id=deployment_id, website_id=website.id
    ).one_or_none()
    if deployment is None:
        raise NotFoundError("Deployment not found.")
    return render_template(
        "sites/deployment.html",
        website=website,
        deployment=deployment,
        logs=deployment.logs,
    )


@bp.route("/<website_id>/edit", methods=["GET", "POST"])
@active_user_required
def edit(website_id: str):
    website = owned_website(current_user, website_id)
    if website.status not in EDITABLE_STATUSES:
        flash("Stop the website before changing its configuration.", "warning")
        return redirect(url_for("sites.detail", website_id=website.id))
    form = WebsiteForm(obj=website)
    _prepare_form(form)
    if form.validate_on_submit():
        payload = _payload_from_form(form)
        try:
            update_website(current_user, website, payload)
        except AppError as exc:
            flash(exc.message, "error")
        else:
            flash("Website configuration updated.", "success")
            return redirect(url_for("sites.detail", website_id=website.id))
    elif not form.is_submitted():
        form.domain_name.data = website.domain.name
        form.repository_full_name.data = website.repository_full_name
        form.framework.data = website.framework.value
        form.internal_port.data = website.internal_port
        form.healthcheck_path.data = website.healthcheck_path
    return render_template(
        "sites/edit.html",
        form=form,
        website=website,
        installations=user_installations(current_user),
    ), 200


@bp.post("/<website_id>/delete")
@active_user_required
def delete(website_id: str):
    website = owned_website(current_user, website_id)
    try:
        delete_website(current_user, website)
    except AppError as exc:
        flash(exc.message, "error")
        return redirect(url_for("sites.detail", website_id=website.id))
    flash("Website deleted.", "info")
    return redirect(url_for("dashboard.index"))


@bp.post("/<website_id>/deploy")
@active_user_required
def deploy(website_id: str):
    website = owned_website(current_user, website_id)
    try:
        deployment = create_deployment(current_user, website)
    except AppError as exc:
        flash(exc.message, "error")
        return redirect(url_for("sites.detail", website_id=website.id))
    flash(
        f"Deployment #{deployment.number} was queued for the connected agent.",
        "success",
    )
    return redirect(
        url_for(
            "sites.deployment_detail",
            website_id=website.id,
            deployment_id=deployment.id,
        )
    )


@bp.post("/<website_id>/start")
@active_user_required
def start(website_id: str):
    website = owned_website(current_user, website_id)
    try:
        request_start(current_user, website)
    except AppError as exc:
        flash(exc.message, "error")
        return redirect(url_for("sites.detail", website_id=website.id))
    flash(
        "Start requested. The agent will confirm when the website is running.",
        "success",
    )
    return redirect(url_for("sites.detail", website_id=website.id))


@bp.post("/<website_id>/stop")
@active_user_required
def stop(website_id: str):
    website = owned_website(current_user, website_id)
    try:
        request_stop(current_user, website)
    except AppError as exc:
        flash(exc.message, "error")
        return redirect(url_for("sites.detail", website_id=website.id))
    flash(
        "Stop requested. The agent will confirm when the container is stopped.",
        "success",
    )
    return redirect(url_for("sites.detail", website_id=website.id))


@bp.post("/<website_id>/backups")
@active_user_required
def create_backup(website_id: str):
    website = owned_website(current_user, website_id)
    try:
        backup = create_website_backup(current_user, website)
    except AppError as exc:
        flash(exc.message, "error")
        return redirect(url_for("sites.detail", website_id=website.id))
    flash(
        f"Backup {backup.id[:8]} was queued. The agent will confirm when it completes.",
        "success",
    )
    return redirect(url_for("sites.detail", website_id=website.id))


@bp.post("/<website_id>/backups/<backup_id>/restore")
@active_user_required
def restore_backup(website_id: str, backup_id: str):
    from ..models import Backup

    website = owned_website(current_user, website_id)
    backup = Backup.query.filter_by(id=backup_id, website_id=website.id).one_or_none()
    if backup is None:
        raise NotFoundError("Backup not found.")
    try:
        request_restore(current_user, website, backup)
    except AppError as exc:
        flash(exc.message, "error")
        return redirect(url_for("sites.detail", website_id=website.id))
    flash("Restore was queued. The website must remain stopped.", "success")
    return redirect(url_for("sites.detail", website_id=website.id))


def _agent_available() -> bool:
    from ..errors import AgentUnavailable
    from ..services.websites import require_available_agent

    try:
        require_available_agent()
    except AgentUnavailable:
        return False
    return True
