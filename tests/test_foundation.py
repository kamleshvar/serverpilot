from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from serverpilot.config import ConfigurationError
from serverpilot.extensions import db
from serverpilot.models import (
    Domain,
    StopReason,
    User,
    UserQuota,
    UserRole,
    Website,
    WebsiteStatus,
)
from serverpilot.services.encryption import EncryptionError, get_encryption
from tests.factories import make_user, make_website


def test_health_endpoint(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["checks"]["database"] == "ok"


def test_landing_page_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"ServerPilot" in response.data
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_api_root_is_versioned(client):
    response = client.get("/api/v1")
    assert response.status_code == 200
    assert response.get_json()["version"] == "v1"


def test_domains_seeded_with_single_user_domain(app):
    domains = Domain.query.order_by(Domain.name).all()
    assert {domain.name for domain in domains} == {
        "example.net",
        "example.org",
        "techorigin.online",
    }
    allowed = [domain for domain in domains if domain.is_user_allowed]
    assert len(allowed) == 1
    assert allowed[0].name == "techorigin.online"


def test_user_quota_defaults_and_shared_limits(app):
    user = make_user("owner@example.com")
    db.session.commit()
    quota = user.quota
    assert quota is not None
    assert quota.max_websites == 5
    assert quota.ram_limit_mb == 1024
    assert quota.storage_limit_mb == 5120
    assert quota.plan_name == "Free"


def test_website_subdomain_is_globally_unique(app):
    owner = make_user("owner@example.com")
    make_website(owner, subdomain="project1")
    db.session.commit()

    with pytest.raises(IntegrityError):
        make_website(owner, subdomain="project1", name="Duplicate")
        db.session.commit()
    db.session.rollback()


def test_admin_forced_stop_fields_persist(app):
    admin = make_user("admin@example.com", role=UserRole.ADMIN, max_websites=10)
    owner = make_user("owner@example.com")
    website = make_website(owner, status=WebsiteStatus.ADMIN_FORCED_STOP)
    website.forced_stop_by_id = admin.id
    website.forced_stop_reason = "Abuse investigation"
    website.stop_reason = StopReason.ADMIN_FORCED_STOP
    db.session.commit()
    website_id = website.id
    db.session.expire_all()

    reloaded = db.session.get(Website, website_id)
    assert reloaded.status == WebsiteStatus.ADMIN_FORCED_STOP
    assert reloaded.forced_stop_by_id == admin.id
    assert reloaded.is_admin_stopped is True


def test_quota_websites_check_constraint(app):
    user = make_user("owner@example.com")
    db.session.commit()
    user.quota.max_websites = 11
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_encryption_roundtrip_and_tamper_detection(app):
    cipher = get_encryption()
    encrypted = cipher.encrypt("ghp_a_very_secret_token")
    assert encrypted and "very_secret" not in encrypted
    assert cipher.decrypt(encrypted) == "ghp_a_very_secret_token"

    tampered = encrypted[:-2] + "AA"
    with pytest.raises(EncryptionError):
        cipher.decrypt(tampered)


def test_user_email_is_normalized(app):
    user = User(email="MixedCase@Example.COM", display_name="Test")
    user.quota = UserQuota()
    db.session.add(user)
    db.session.commit()
    assert user.email == "mixedcase@example.com"


def test_production_refuses_sqlite_and_missing_secrets():
    with pytest.raises(ConfigurationError) as excinfo:
        from serverpilot import create_app

        create_app(
            "production",
            {
                "SECRET_KEY": "",
                "ENCRYPTION_KEY": "",
                "ADMIN_PASSWORD_HASH": "",
                "ADMIN_EMAIL": "",
                "ADMIN_USERNAME": "",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "APP_URL": "http://insecure.example.com",
                "DOMAINS": ("techorigin.online",),
                "USER_ALLOWED_DOMAIN": "techorigin.online",
            },
        )
    message = str(excinfo.value)
    assert "SECRET_KEY" in message
    assert "SQLite" in message
    assert "https" in message


def test_cli_seed_core(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["seed-core"])
    assert result.exit_code == 0
    assert "Core data synchronized" in result.output


def test_cli_create_admin_is_database_backed(app):
    from werkzeug.security import generate_password_hash

    app.config["ADMIN_PASSWORD_HASH"] = generate_password_hash("a-strong-password")
    app.config["ADMIN_EMAIL"] = "operator@example.com"
    app.config["ADMIN_GITHUB_ID"] = "999001"
    runner = app.test_cli_runner()
    result = runner.invoke(args=["create-admin"])
    assert result.exit_code == 0, result.output
    admin = User.query.filter_by(email="operator@example.com").one()
    assert admin.is_admin
    assert admin.quota is not None
    assert admin.identities[0].provider_user_id == "999001"
