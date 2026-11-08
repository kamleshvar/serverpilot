from __future__ import annotations

from datetime import timedelta

from werkzeug.security import generate_password_hash

import serverpilot.blueprints.auth as auth_blueprint
from serverpilot.decorators import admin_deployment_required
from serverpilot.extensions import db
from serverpilot.models import (
    AdminAction,
    AdminActionResult,
    AuthAttempt,
    IdentityProvider,
    User,
    UserIdentity,
    UserRole,
    UserSession,
)
from serverpilot.services.admin_auth import (
    ADMIN_AUTH_AT_KEY,
    ADMIN_DEPLOY_AUTH_AT_KEY,
    ADMIN_ID_KEY,
    admin_deployment_authorized,
    grant_admin_deployment_authorization,
)
from serverpilot.services.oauth import OAuthProfile
from serverpilot.utils import utcnow
from tests.factories import make_user


def _profile(
    *,
    provider: IdentityProvider = IdentityProvider.GOOGLE,
    subject: str = "google-subject-1",
    email: str = "newuser@example.com",
    verified: bool = True,
    name: str = "New User",
) -> OAuthProfile:
    return OAuthProfile(
        provider=provider,
        subject=subject,
        email=email,
        email_verified=verified,
        display_name=name,
        login="newuser",
        avatar_url=None,
        access_token="plaintext-never-stored",
        refresh_token=None,
        expires_at=None,
        scopes="openid email profile",
    )


def _start_login(client, *, mode: str = "login", next_url: str = "/dashboard"):
    with client.session_transaction() as sess:
        sess["oauth_mode"] = mode
        sess["oauth_next"] = next_url
        sess["oauth_started_at"] = utcnow().isoformat()


def _oauth_login(client, monkeypatch, **profile_kwargs):
    profile = _profile(**profile_kwargs)
    monkeypatch.setattr(
        auth_blueprint, "complete_authorize", lambda *args, **kwargs: profile
    )
    _start_login(client)
    response = client.get("/auth/google/callback")
    assert response.status_code == 302
    return response


def test_login_page_renders_when_oauth_not_configured(client):
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert b"Sign-in is not configured" in response.data


def test_dashboard_requires_authentication(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_oauth_callback_creates_account_and_tracked_session(client, monkeypatch):
    response = _oauth_login(client, monkeypatch)
    assert response.headers["Location"].endswith("/dashboard")

    user = User.query.filter_by(email="newuser@example.com").one()
    assert user.quota.plan_name == "Free"
    assert user.quota.max_websites == 5
    identity = UserIdentity.query.one()
    assert identity.provider == IdentityProvider.GOOGLE
    assert identity.provider_user_id == "google-subject-1"
    assert "plaintext-never-stored" not in (identity.access_token_encrypted or "")

    tracked = UserSession.query.one()
    assert tracked.user_id == user.id
    assert tracked.revoked_at is None

    with client.session_transaction() as sess:
        assert sess["user_session_id"] == tracked.id
        assert sess["_user_id"] == user.id

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert b"Welcome back" in dashboard.data


def test_stale_oauth_state_is_rejected_and_recorded(client, monkeypatch):
    profile = _profile()
    monkeypatch.setattr(
        auth_blueprint, "complete_authorize", lambda *args, **kwargs: profile
    )
    with client.session_transaction() as sess:
        sess["oauth_mode"] = "login"
        sess["oauth_next"] = "/dashboard"
        sess["oauth_started_at"] = (utcnow() - timedelta(minutes=11)).isoformat()

    response = client.get("/auth/google/callback")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")
    assert User.query.count() == 0
    attempt = AuthAttempt.query.order_by(AuthAttempt.created_at.desc()).first()
    assert attempt is not None
    assert attempt.success is False
    assert attempt.reason == "invalid_or_expired_oauth_state"


def test_revoked_server_side_session_blocks_dashboard(client, monkeypatch):
    _oauth_login(client, monkeypatch)
    tracked = UserSession.query.one()
    tracked.revoked_at = utcnow()
    db.session.commit()

    response = client.get("/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")
    with client.session_transaction() as sess:
        assert "user_session_id" not in sess
        assert "_user_id" not in sess


def test_admin_console_requires_separate_authentication(client):
    response = client.get("/techorigin/")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/techorigin/login")


def test_admin_login_rejects_invalid_credentials(app, client):
    app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash("correct-password")
    make_user("admin@example.com", role=UserRole.ADMIN)
    db.session.commit()

    response = client.post(
        "/techorigin/login",
        data={"passcode": "wrong-password"},
    )
    assert response.status_code == 200
    assert b"Invalid administrator credentials" in response.data
    with client.session_transaction() as sess:
        assert ADMIN_ID_KEY not in sess

    failed = AdminAction.query.filter_by(action="admin_login_failed").one()
    assert failed.result == AdminActionResult.DENIED
    assert failed.details["reason"] == "invalid_credentials"


def test_admin_login_establishes_independent_session_and_renders_dashboard(app, client):
    app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash("correct-password")
    admin = make_user("admin@example.com", role=UserRole.ADMIN)
    db.session.commit()

    response = client.post(
        "/techorigin/login",
        data={"passcode": "correct-password"},
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/techorigin/"

    with client.session_transaction() as sess:
        assert sess[ADMIN_ID_KEY] == admin.id
        assert ADMIN_AUTH_AT_KEY in sess
        assert "_user_id" not in sess

    dashboard = client.get("/techorigin/")
    assert dashboard.status_code == 200
    assert b"Global overview" in dashboard.data
    assert AdminAction.query.filter_by(action="admin_login").count() == 1


def test_admin_deployment_gate_rejects_until_authorized(app, client):
    app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash("correct-password")
    app.config["ADMIN_DEPLOYMENT_AUTH_REQUIRED"] = True
    make_user("admin@example.com", role=UserRole.ADMIN)
    db.session.commit()

    @app.get("/__test/deployment-action")
    @admin_deployment_required
    def protected_action():
        return "deployment-action"

    client.post(
        "/techorigin/login",
        data={"passcode": "correct-password"},
    )

    denied = client.get("/__test/deployment-action")
    assert denied.status_code == 302
    assert denied.headers["Location"].startswith("/techorigin/deployment-auth")

    with client.session_transaction() as sess:
        sess[ADMIN_DEPLOY_AUTH_AT_KEY] = utcnow().isoformat()

    allowed = client.get("/__test/deployment-action")
    assert allowed.status_code == 200
    assert allowed.data == b"deployment-action"

    with client.session_transaction() as sess:
        sess[ADMIN_DEPLOY_AUTH_AT_KEY] = (
            utcnow()
            - app.config["ADMIN_DEPLOYMENT_AUTH_LIFETIME"]
            - timedelta(seconds=1)
        ).isoformat()

    expired = client.get("/__test/deployment-action")
    assert expired.status_code == 302
    assert expired.headers["Location"].startswith("/techorigin/deployment-auth")


def test_admin_deployment_grant_requires_configured_github_identity(app):
    admin = make_user("admin@example.com", role=UserRole.ADMIN)
    db.session.commit()
    profile = _profile(
        provider=IdentityProvider.GITHUB,
        subject=app.config["ADMIN_GITHUB_ID"],
        email=None,
        verified=False,
        name="Administrator",
    )

    with app.test_request_context("/"):
        from flask import session

        session[ADMIN_ID_KEY] = admin.id
        session[ADMIN_AUTH_AT_KEY] = utcnow().isoformat()
        grant_admin_deployment_authorization(admin, profile)
        assert admin_deployment_authorized() is True

    identity = UserIdentity.query.one()
    assert identity.provider == IdentityProvider.GITHUB
    assert identity.user_id == admin.id
    assert AdminAction.query.filter_by(action="admin_deployment_auth").count() == 1
