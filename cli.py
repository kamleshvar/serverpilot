"""ServerPilot operator CLI (`flask --app wsgi ...`)."""

from __future__ import annotations

import secrets
from datetime import timedelta

import click
from cryptography.fernet import Fernet
from flask import Flask
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash

from .extensions import db
from .models import (
    AgentNonce,
    IdentityProvider,
    User,
    UserIdentity,
    UserQuota,
    UserRole,
    UserSession,
    UserStatus,
)
from .services.domains import seed_configured_domains
from .services.settings import seed_default_settings
from .utils import utcnow


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    @click.option(
        "--force",
        is_flag=True,
        help="Allow database creation in non-development environments.",
    )
    def init_db(force: bool) -> None:
        """Create tables directly (development convenience) and seed core data.

        Production and staging must use 'flask db upgrade'.
        """
        if app.config["ENV_NAME"] not in {"development", "testing"} and not force:
            raise click.ClickException(
                "init-db is a development convenience. Use 'flask db upgrade' "
                "and 'flask seed-core' instead (or pass --force)."
            )
        db.create_all()
        seed_configured_domains(commit=False)
        seed_default_settings(commit=False)
        db.session.commit()
        click.echo("Database tables created and core data seeded.")
        for domain in app.config["DOMAINS"]:
            click.echo(f"  domain: {domain}")

    @app.cli.command("seed-core")
    def seed_core() -> None:
        """Synchronize configured domains and defaults into an existing schema."""
        try:
            seed_configured_domains(commit=False)
            seed_default_settings(commit=False)
            db.session.commit()
        except OperationalError as exc:
            db.session.rollback()
            raise click.ClickException(
                "Database schema is missing. Run 'flask db upgrade' first."
            ) from exc
        click.echo("Core data synchronized.")
        click.echo(f"User domain: {app.config.get('USER_ALLOWED_DOMAIN')}")

    @app.cli.command("seed-settings")
    def seed_settings() -> None:
        """Insert any missing platform settings defaults."""
        seed_default_settings()
        click.echo("Platform settings seeded.")

    @app.cli.command("hash-password")
    @click.option(
        "--password", help="Password to hash (avoid shell history; omit for prompt)."
    )
    def hash_password(password: str | None) -> None:
        """Generate an ADMIN_PASSWORD_HASH value."""
        if not password:
            password = click.prompt(
                "Admin password", hide_input=True, confirmation_prompt=True
            )
        if len(password) < 12:
            raise click.ClickException(
                "Use an admin password of at least 12 characters."
            )
        click.echo(generate_password_hash(password))
        click.echo("Store the value above in ADMIN_PASSWORD_HASH in your .env file.")

    @app.cli.command("generate-secrets")
    def generate_secrets() -> None:
        """Generate SECRET_KEY and ENCRYPTION_KEY values (never commit them)."""
        click.echo("SECRET_KEY=" + secrets.token_hex(32))
        click.echo("ENCRYPTION_KEY=" + Fernet.generate_key().decode())
        click.echo("AGENT_SIGNING_SECRET=" + secrets.token_hex(32))
        click.echo("AGENT_BOOTSTRAP_TOKEN=" + secrets.token_urlsafe(32))

    @app.cli.command("create-admin")
    @click.option("--email", help="Authorized admin email (defaults to ADMIN_EMAIL).")
    @click.option("--name", help="Display name.")
    @click.option(
        "--github-id",
        help="Authorized GitHub numeric ID (defaults to ADMIN_GITHUB_ID).",
    )
    @click.option(
        "--promote", is_flag=True, help="Promote an existing normal user to admin."
    )
    def create_admin(
        email: str | None, name: str | None, github_id: str | None, promote: bool
    ) -> None:
        """Create or update the database-backed admin identity.

        ADMIN_PASSWORD_HASH is read from the environment; the password itself is
        never stored in the database.
        """
        email = (email or app.config.get("ADMIN_EMAIL") or "").strip().lower()
        if not email:
            raise click.ClickException(
                "Set ADMIN_EMAIL or pass --email. The admin identity must be "
                "explicitly provisioned; it is never created from an arbitrary "
                "OAuth login."
            )
        github_id = (
            github_id or app.config.get("ADMIN_GITHUB_ID") or ""
        ).strip() or None
        if not app.config.get("ADMIN_PASSWORD_HASH"):
            click.echo(
                "WARNING: ADMIN_PASSWORD_HASH is empty; admin password login will be disabled.",
                err=True,
            )

        try:
            user = User.query.filter_by(email=email).one_or_none()
            if user is None:
                user = User(
                    email=email,
                    display_name=name or "Administrator",
                    role=UserRole.ADMIN,
                    status=UserStatus.ACTIVE,
                )
                db.session.add(user)
                db.session.flush()
                db.session.add(
                    UserQuota(
                        user_id=user.id,
                        plan_name="Administrator",
                        max_websites=app.config["MAX_ADMIN_WEBSITES"],
                        ram_limit_mb=app.config["DEFAULT_RAM_LIMIT_MB"],
                        storage_limit_mb=app.config["DEFAULT_STORAGE_LIMIT_MB"],
                        cpu_limit=1.0,
                    )
                )
                click.echo(f"Created admin user {email} ({user.id}).")
            else:
                if not user.is_admin and not promote:
                    raise click.ClickException(
                        f"{email} already exists as a normal user. Re-run with "
                        "--promote only if this promotion is intentional."
                    )
                user.role = UserRole.ADMIN
                if user.status == UserStatus.DELETED:
                    user.status = UserStatus.ACTIVE
                    user.deleted_at = None
                if not user.quota:
                    db.session.add(
                        UserQuota(
                            user_id=user.id,
                            plan_name="Administrator",
                            max_websites=app.config["MAX_ADMIN_WEBSITES"],
                            ram_limit_mb=app.config["DEFAULT_RAM_LIMIT_MB"],
                            storage_limit_mb=app.config["DEFAULT_STORAGE_LIMIT_MB"],
                        )
                    )
                click.echo(f"Updated admin user {email}.")

            if github_id:
                identity = UserIdentity.query.filter_by(
                    provider=IdentityProvider.GITHUB,
                    provider_user_id=github_id,
                ).one_or_none()
                if identity and identity.user_id != user.id:
                    raise click.ClickException(
                        "That GitHub identity is already linked to another user."
                    )
                own_identity = UserIdentity.query.filter_by(
                    user_id=user.id, provider=IdentityProvider.GITHUB
                ).one_or_none()
                if own_identity is None:
                    db.session.add(
                        UserIdentity(
                            user_id=user.id,
                            provider=IdentityProvider.GITHUB,
                            provider_user_id=github_id,
                            provider_email=email,
                            email_verified=False,
                        )
                    )
                    click.echo(f"Linked authorized GitHub ID {github_id}.")
                elif own_identity.provider_user_id != github_id:
                    own_identity.provider_user_id = github_id
                    click.echo(f"Replaced linked GitHub ID with {github_id}.")

            db.session.commit()
        except click.ClickException:
            db.session.rollback()
            raise
        except Exception as exc:
            db.session.rollback()
            raise click.ClickException(f"Could not create admin: {exc}") from exc

        click.echo(
            "Admin provisioning complete. Restart the web service to apply .env changes."
        )

    @app.cli.command("check-config")
    def check_config() -> None:
        """Print effective non-secret configuration and validation warnings."""
        click.echo(f"Environment: {app.config['ENV_NAME']}")
        click.echo(f"App URL:     {app.config['APP_URL']}")
        click.echo(
            f"Database:    {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1]}"
        )
        click.echo(f"Domains:     {', '.join(app.config['DOMAINS']) or '(none)'}")
        click.echo(f"User domain: {app.config.get('USER_ALLOWED_DOMAIN')}")
        click.echo(
            "Integrations: "
            f"google={'on' if app.config['GOOGLE_OAUTH_ENABLED'] else 'off'} "
            f"github={'on' if app.config['GITHUB_OAUTH_ENABLED'] else 'off'} "
            f"github_app={'on' if app.config['GITHUB_APP_ENABLED'] else 'off'} "
            f"cloudflare={'on' if app.config['CLOUDFLARE_ENABLED'] else 'off'}"
        )
        for warning in app.config.get("CONFIG_WARNINGS", []):
            click.echo(f"WARNING: {warning}")

    @app.cli.command("sync-cloudflare-domains")
    def sync_cloudflare_domains() -> None:
        """Resolve and store Cloudflare zone IDs for configured domains."""
        from .errors import AppError
        from .services.cloudflare import sync_domains

        try:
            domains = sync_domains()
        except AppError as exc:
            db.session.rollback()
            raise click.ClickException(exc.message) from exc
        click.echo(f"Synchronized {len(domains)} Cloudflare domains.")

    @app.cli.command("sync-cloudflare-dns")
    def sync_cloudflare_dns() -> None:
        """Create or update tunnel CNAME records for every active website."""
        from .errors import AppError
        from .services.cloudflare import sync_all_website_dns

        try:
            count = sync_all_website_dns()
        except AppError as exc:
            db.session.rollback()
            raise click.ClickException(exc.message) from exc
        click.echo(f"Synchronized DNS for {count} websites.")

    @app.cli.command("purge-expired")
    def purge_expired() -> None:
        """Delete expired sessions, agent nonces and old failed auth attempts."""
        now = utcnow()
        sessions = UserSession.query.filter(
            (UserSession.expires_at < now) | (UserSession.revoked_at.isnot(None))
        ).delete(synchronize_session=False)
        nonces = AgentNonce.query.filter(AgentNonce.expires_at < now).delete(
            synchronize_session=False
        )
        db.session.commit()
        click.echo(f"Removed {sessions} sessions and {nonces} agent nonces.")

    @app.cli.command("expire-sessions")
    @click.option("--email", required=True)
    def expire_sessions(email: str) -> None:
        """Revoke all sessions for a user (incident response)."""
        user = User.query.filter_by(email=email.strip().lower()).one_or_none()
        if user is None:
            raise click.ClickException("User not found.")
        count = UserSession.query.filter_by(user_id=user.id, revoked_at=None).update(
            {"revoked_at": utcnow()}, synchronize_session=False
        )
        db.session.commit()
        click.echo(f"Revoked {count} sessions for {user.email}.")

    @app.cli.command("prune-sessions")
    @click.option("--days", default=30, show_default=True)
    def prune_sessions(days: int) -> None:
        """Remove expired session records older than N days."""
        cutoff = utcnow() - timedelta(days=days)
        count = UserSession.query.filter(UserSession.expires_at < cutoff).delete(
            synchronize_session=False
        )
        db.session.commit()
        click.echo(f"Removed {count} old session records.")
