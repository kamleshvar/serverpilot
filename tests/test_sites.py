from __future__ import annotations

import pytest

import serverpilot.blueprints.sites as sites_blueprint
from serverpilot.errors import PermissionDenied, QuotaExceededError
from serverpilot.extensions import db
from serverpilot.models import (
    Framework,
    GithubInstallation,
    GithubInstallationStatus,
    Website,
    WebsiteStatus,
)
from serverpilot.services.domains import resolve_domain_for_user
from serverpilot.services.github_app import GithubRepository
from serverpilot.services.quota import assert_website_ram_available, quota_snapshot
from serverpilot.services.websites import WebsiteInput, create_website, delete_website
from tests.factories import make_user, make_website, sign_in


def _installation(user, installation_id: int = 7001) -> GithubInstallation:
    installation = GithubInstallation(
        installation_id=installation_id,
        user_id=user.id,
        account_login="owner",
        account_type="User",
        repository_selection="all",
        status=GithubInstallationStatus.ACTIVE,
    )
    db.session.add(installation)
    db.session.commit()
    return installation


def _payload(subdomain: str = "customer-portal", domain: str = "techorigin.online"):
    return WebsiteInput(
        name="Customer Portal",
        subdomain=subdomain,
        domain_name=domain,
        repository_full_name="owner/repository",
        branch="main",
        framework=Framework.FLASK,
        build_command="pip install -r requirements.txt",
        start_command="gunicorn app:app --bind 0.0.0.0:8000",
        internal_port=8000,
        healthcheck_path="/health",
    )


def test_new_site_page_asks_to_link_github_identity(client):
    user = make_user("owner@example.com")
    db.session.commit()
    sign_in(client, user)

    response = client.get("/sites/new")
    assert response.status_code == 200
    assert b"Link a GitHub account first" in response.data


def test_new_site_page_loads_oauth_repositories(app, client, monkeypatch):
    from serverpilot.models import IdentityProvider, UserIdentity

    user = make_user("owner@example.com")
    db.session.add(
        UserIdentity(
            user_id=user.id,
            provider=IdentityProvider.GITHUB,
            provider_user_id="123",
            provider_login="owner",
            email_verified=True,
        )
    )
    db.session.commit()
    sign_in(client, user)

    monkeypatch.setattr(
        sites_blueprint,
        "oauth_repositories_for",
        lambda current_user: [
            GithubRepository(
                full_name="owner/repo-a",
                default_branch="main",
                private=False,
                installation_id=0,
            )
        ],
    )
    response = client.get("/sites/new")
    assert response.status_code == 200
    assert b"owner/repo-a" in response.data


def test_create_website_via_oauth_fallback(app, client, monkeypatch):
    from serverpilot.models import IdentityProvider, UserIdentity

    user = make_user("owner@example.com")
    db.session.add(
        UserIdentity(
            user_id=user.id,
            provider=IdentityProvider.GITHUB,
            provider_user_id="123",
            provider_login="owner",
            email_verified=True,
        )
    )
    db.session.commit()
    sign_in(client, user)

    repo = GithubRepository(
        full_name="owner/repo-a",
        default_branch="main",
        private=False,
        installation_id=0,
    )
    monkeypatch.setattr(sites_blueprint, "github_app_configured", lambda: False)
    monkeypatch.setattr(
        sites_blueprint, "verify_repository_user_token", lambda u, n: repo
    )
    response = client.post(
        "/sites/new",
        data={
            "name": "OAuth Site",
            "domain_name": "techorigin.online",
            "subdomain": "oauth-site",
            "repository_full_name": "owner/repo-a",
            "branch": "main",
            "framework": "flask",
            "internal_port": "8000",
            "healthcheck_path": "/",
        },
    )
    assert response.status_code == 302, response.data
    website = Website.query.filter_by(subdomain="oauth-site").one()
    assert website.repository_full_name == "owner/repo-a"
    assert website.branch == "main"
    assert website.github_installation_id is None
    assert website.build_config.get("source") == "github_oauth"


def test_connections_page_renders_without_integrations(client):
    user = make_user("owner@example.com")
    db.session.commit()
    sign_in(client, user)

    response = client.get("/settings/connections")
    assert response.status_code == 200
    assert b"Sign-in identities" in response.data
    assert b"GitHub App integration is not configured" in response.data


def test_website_creation_verifies_repository_and_renders_detail(
    app, client, monkeypatch
):
    user = make_user("owner@example.com")
    installation = _installation(user)
    db.session.commit()
    sign_in(client, user)

    repository = GithubRepository(
        full_name="owner/repository",
        default_branch="main",
        private=True,
        installation_id=installation.installation_id,
    )
    monkeypatch.setattr(sites_blueprint, "github_app_configured", lambda: True)
    monkeypatch.setattr(
        sites_blueprint,
        "verify_repository",
        lambda current_user, full_name: (installation, repository),
    )

    response = client.post(
        "/sites/new",
        data={
            "name": "Customer Portal",
            "subdomain": "customer-portal",
            "domain_name": "techorigin.online",
            "repository_full_name": "owner/repository",
            "branch": "main",
            "framework": "flask",
            "root_directory": "",
            "build_command": "pip install -r requirements.txt",
            "start_command": "gunicorn app:app --bind 0.0.0.0:8000",
            "internal_port": "8000",
            "healthcheck_path": "/health",
            "auto_deploy_enabled": "y",
        },
    )
    assert response.status_code == 302

    website = Website.query.one()
    assert website.owner_id == user.id
    assert website.fqdn == "customer-portal.techorigin.online"
    assert website.repository_full_name == "owner/repository"
    assert website.github_installation_id == installation.id
    assert website.container_name.startswith("sp-")
    assert website.status == WebsiteStatus.PENDING

    detail = client.get(f"/sites/{website.id}")
    assert detail.status_code == 200
    assert b"customer-portal.techorigin.online" in detail.data
    assert b"Deployment engine not connected" in detail.data


def test_user_cannot_select_another_configured_domain(app):
    user = make_user("owner@example.com")
    db.session.commit()
    from serverpilot.models import Domain

    example_org = Domain.query.filter_by(name="example.org").one()
    with pytest.raises(PermissionDenied):
        resolve_domain_for_user(user, example_org.name)


def test_shared_storage_quota_blocks_sixth_website(app):
    user = make_user("owner@example.com", storage_limit_mb=10240)
    installation = _installation(user)
    db.session.commit()

    for index in range(5):
        create_website(
            user,
            _payload(subdomain=f"site-{index}"),
            github_installation=installation,
            repository_default_branch="main",
        )
    snapshot = quota_snapshot(user)
    assert snapshot.websites_used == 5
    assert snapshot.storage_reserved_mb == snapshot.storage_limit_mb

    with pytest.raises(QuotaExceededError):
        create_website(
            user,
            _payload(subdomain="site-6"),
            github_installation=installation,
            repository_default_branch="main",
        )


def test_shared_ram_quota_blocks_start_beyond_account_limit(app):
    user = make_user("owner@example.com")
    db.session.commit()
    for index in range(4):
        make_website(
            user,
            subdomain=f"running-{index}",
            status=WebsiteStatus.RUNNING,
            ram_limit_mb=256,
        )
    fifth = make_website(
        user, subdomain="blocked", status=WebsiteStatus.USER_STOPPED, ram_limit_mb=256
    )
    db.session.commit()

    with pytest.raises(QuotaExceededError):
        assert_website_ram_available(user, fifth)


def test_delete_soft_deletes_and_releases_fqdn(app):
    user = make_user("owner@example.com")
    db.session.commit()
    website = make_website(
        user, subdomain="reusable", status=WebsiteStatus.USER_STOPPED
    )
    db.session.commit()
    original_id = website.id

    delete_website(user, website)
    assert website.status == WebsiteStatus.DELETED
    assert website.deleted_at is not None
    assert website.fqdn.startswith("deleted-")
    assert website.container_name is None

    replacement = make_website(user, subdomain="reusable", status=WebsiteStatus.PENDING)
    db.session.commit()
    assert replacement.id != original_id
    assert replacement.fqdn == "reusable.techorigin.online"


def test_create_website_redirects_to_deployment_logs(app, client, monkeypatch):
    from types import SimpleNamespace

    user = make_user("owner@example.com")
    installation = _installation(user)
    db.session.commit()
    sign_in(client, user)

    repository = GithubRepository(
        full_name="owner/repository",
        default_branch="main",
        private=True,
        installation_id=installation.installation_id,
    )
    monkeypatch.setattr(sites_blueprint, "github_app_configured", lambda: True)
    monkeypatch.setattr(
        sites_blueprint,
        "verify_repository",
        lambda current_user, full_name: (installation, repository),
    )
    fake_deployment = SimpleNamespace(id="dep-1", number=1)
    monkeypatch.setattr(
        sites_blueprint, "create_deployment", lambda u, w: fake_deployment
    )

    response = client.post(
        "/sites/new",
        data={
            "name": "Customer Portal",
            "subdomain": "instant-deploy",
            "domain_name": "techorigin.online",
            "repository_full_name": "owner/repository",
            "branch": "main",
            "framework": "flask",
            "internal_port": "8000",
            "healthcheck_path": "/health",
            "auto_deploy_enabled": "y",
        },
    )
    assert response.status_code == 302
    website = Website.query.one()
    assert response.headers["Location"].endswith(
        f"/sites/{website.id}/deployments/dep-1"
    )


def test_deploy_now_redirects_to_deployment_logs(app, client, monkeypatch):
    from types import SimpleNamespace

    user = make_user("owner@example.com")
    installation = _installation(user)
    db.session.commit()
    website = create_website(
        user,
        _payload(subdomain="now-deploying"),
        github_installation=installation,
        repository_default_branch="main",
    )
    sign_in(client, user)

    fake_deployment = SimpleNamespace(id="dep-9", number=2)
    monkeypatch.setattr(
        sites_blueprint, "create_deployment", lambda u, w: fake_deployment
    )
    response = client.post(f"/sites/{website.id}/deploy")
    assert response.status_code == 302
    assert response.headers["Location"].endswith(
        f"/sites/{website.id}/deployments/dep-9"
    )
