"""GitHub App authentication, installation ownership and repository access.

The panel never trusts a client-supplied installation ID. An installation is
linked to an account only after GitHub confirms that the installation belongs
to the user's GitHub login or to an organization the user is an active member
of. Repository access is then checked with an installation token.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import jwt
import requests
from flask import current_app

from ..errors import (
    ConflictError,
    IntegrationNotConfigured,
    PermissionDenied,
    ValidationError,
)
from ..extensions import db
from ..models import (
    GithubInstallation,
    GithubInstallationStatus,
    IdentityProvider,
    User,
    UserIdentity,
)
from ..utils import utcnow
from .oauth import get_access_token

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT = (5, 20)
USER_AGENT = "ServerPilot/1.0"


class GithubAppError(IntegrationNotConfigured):
    code = "github_app_error"
    default_message = "GitHub App authentication failed."


@dataclass(frozen=True)
class GithubRepository:
    full_name: str
    default_branch: str
    private: bool
    installation_id: int


def github_app_configured() -> bool:
    return bool(
        current_app.config.get("GITHUB_APP_ID")
        and (
            current_app.config.get("GITHUB_APP_PRIVATE_KEY")
            or current_app.config.get("GITHUB_APP_PRIVATE_KEY_PATH")
        )
    )


def _require_configured() -> None:
    if not github_app_configured():
        raise IntegrationNotConfigured(
            "GitHub App is not configured. Set GITHUB_APP_ID and the app private "
            "key on the server before connecting repositories."
        )


def app_install_url() -> str | None:
    if current_app.config.get("GITHUB_APP_SETUP_URL"):
        return str(current_app.config["GITHUB_APP_SETUP_URL"])
    slug = current_app.config.get("GITHUB_APP_SLUG")
    if slug:
        return f"https://github.com/apps/{slug}/installations/new"
    return None


def _private_key() -> str:
    raw = current_app.config.get("GITHUB_APP_PRIVATE_KEY") or ""
    if not raw:
        path = current_app.config.get("GITHUB_APP_PRIVATE_KEY_PATH")
        if path:
            try:
                raw = Path(path).read_text(encoding="utf-8")
            except OSError as exc:
                raise GithubAppError(
                    "The configured GitHub App private key could not be read."
                ) from exc
    raw = raw.replace("\\n", "\n").strip()
    if "BEGIN" not in raw:
        raise GithubAppError("The GitHub App private key is not a PEM key.")
    return raw


def app_jwt() -> str:
    _require_configured()
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 9 * 60,
        "iss": str(current_app.config["GITHUB_APP_ID"]),
    }
    try:
        return jwt.encode(payload, _private_key(), algorithm="RS256")
    except Exception as exc:
        logger.exception("Could not sign GitHub App JWT")
        raise GithubAppError("The GitHub App private key is invalid.") from exc


def _headers(token: str, *, bearer_prefix: str = "Bearer") -> dict[str, str]:
    return {
        "Authorization": f"{bearer_prefix} {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }


def _github_request(
    method: str,
    path: str,
    *,
    token: str,
    bearer_prefix: str = "Bearer",
    allowed: tuple[int, ...] = (200,),
    json: dict | None = None,
) -> requests.Response:
    try:
        response = requests.request(
            method,
            f"{GITHUB_API}{path}",
            headers=_headers(token, bearer_prefix=bearer_prefix),
            json=json,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("GitHub API request failed path=%s", path)
        raise GithubAppError("GitHub could not be reached. Try again shortly.") from exc
    if response.status_code not in allowed:
        logger.warning(
            "GitHub API rejected path=%s status=%s", path, response.status_code
        )
        raise GithubAppError(
            "GitHub rejected the request. Check the App installation and permissions."
        )
    return response


def get_installation_from_github(installation_id: int) -> dict[str, Any]:
    _require_configured()
    response = _github_request(
        "GET", f"/app/installations/{int(installation_id)}", token=app_jwt()
    )
    data = response.json()
    if not isinstance(data, dict) or "id" not in data:
        raise GithubAppError("GitHub returned an invalid installation record.")
    return data


def installation_token(installation_id: int) -> str:
    _require_configured()
    response = _github_request(
        "POST",
        f"/app/installations/{int(installation_id)}/access_tokens",
        token=app_jwt(),
    )
    token = (response.json() or {}).get("token")
    if not token:
        raise GithubAppError("GitHub did not issue an installation token.")
    return token


def installation_token_for_commit(
    installation_id: int, full_name: str, ref: str
) -> tuple[str, dict[str, Any]]:
    """Return an installation token plus commit metadata for a repository ref."""
    token = installation_token(installation_id)
    response = _github_request(
        "GET",
        f"/repos/{full_name}/commits/{quote(ref, safe='')}",
        token=token,
    )
    data = response.json()
    commit = data.get("commit") or {}
    if not data.get("sha"):
        raise GithubAppError("GitHub did not return a commit for that branch.")
    return token, {
        "sha": data["sha"],
        "message": (commit.get("message") or "")[:4000],
        "author": (
            (commit.get("author") or {}).get("name")
            or (data.get("author") or {}).get("login")
            or ""
        )[:255],
    }


def _github_identity_for(user: User) -> UserIdentity | None:
    return UserIdentity.query.filter_by(
        user_id=user.id, provider=IdentityProvider.GITHUB
    ).one_or_none()


def _verify_installation_owner(user: User, installation: dict[str, Any]) -> None:
    identity = _github_identity_for(user)
    if identity is None:
        raise PermissionDenied(
            "Link a GitHub account first, then connect this GitHub App installation."
        )
    token = get_access_token(identity)
    if not token:
        raise PermissionDenied(
            "Your GitHub authorization expired. Sign in with GitHub again before "
            "connecting an installation."
        )

    account = installation.get("account") or {}
    account_login = str(account.get("login") or "")
    account_type = str(account.get("type") or "").lower()
    if not account_login:
        raise GithubAppError("GitHub did not identify the installation owner.")

    if account_type == "user":
        if not identity.provider_login or not hmac.compare_digest(
            identity.provider_login.lower(), account_login.lower()
        ):
            raise PermissionDenied(
                "This GitHub App installation belongs to a different GitHub account."
            )
        return

    try:
        response = requests.get(
            f"{GITHUB_API}/user/memberships/orgs/{account_login}",
            headers=_headers(token, bearer_prefix="token"),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GithubAppError(
            "GitHub could not verify organization membership."
        ) from exc
    if response.status_code != 200:
        raise PermissionDenied(
            "Active membership in the organization that owns this installation is "
            "required. Re-authorize GitHub with read:org access if needed."
        )
    membership = response.json() or {}
    if membership.get("state") != "active":
        raise PermissionDenied(
            "Your organization membership is not active, so this installation "
            "cannot be connected."
        )


def link_installation(user: User, installation_id: int) -> GithubInstallation:
    _require_configured()
    remote = get_installation_from_github(installation_id)
    if int(remote.get("id", 0)) != int(installation_id):
        raise GithubAppError("GitHub returned a mismatched installation.")
    _verify_installation_owner(user, remote)

    installation = GithubInstallation.query.filter_by(
        installation_id=int(installation_id)
    ).one_or_none()
    if installation is not None and installation.user_id not in {None, user.id}:
        raise ConflictError(
            "This GitHub App installation is already connected to another ServerPilot account."
        )

    account = remote.get("account") or {}
    if installation is None:
        installation = GithubInstallation(
            installation_id=int(installation_id),
            account_login=str(account.get("login") or "unknown")[:191],
            account_type=str(account.get("type") or "User")[:32],
            target_type=remote.get("target_type"),
            repository_selection=remote.get("repository_selection") or "selected",
        )
        db.session.add(installation)
    installation.user_id = user.id
    installation.account_login = str(
        account.get("login") or installation.account_login
    )[:191]
    installation.account_type = str(account.get("type") or installation.account_type)[
        :32
    ]
    installation.target_type = remote.get("target_type")
    installation.repository_selection = (
        remote.get("repository_selection") or installation.repository_selection
    )
    installation.permissions = remote.get("permissions") or {}
    installation.events = remote.get("events") or []
    installation.status = GithubInstallationStatus.ACTIVE
    installation.suspended_at = None
    installation.last_synced_at = utcnow()
    db.session.commit()
    return installation


def sync_installation(installation: GithubInstallation) -> None:
    remote = get_installation_from_github(installation.installation_id)
    account = remote.get("account") or {}
    installation.account_login = str(
        account.get("login") or installation.account_login
    )[:191]
    installation.account_type = str(account.get("type") or installation.account_type)[
        :32
    ]
    installation.target_type = remote.get("target_type")
    installation.repository_selection = (
        remote.get("repository_selection") or installation.repository_selection
    )
    installation.permissions = remote.get("permissions") or {}
    installation.events = remote.get("events") or []
    installation.suspended_at = utcnow() if remote.get("suspended_at") else None
    installation.status = (
        GithubInstallationStatus.SUSPENDED
        if remote.get("suspended_at")
        else GithubInstallationStatus.ACTIVE
    )
    installation.last_synced_at = utcnow()
    db.session.commit()


def user_installations(user: User) -> list[GithubInstallation]:
    return (
        GithubInstallation.query.filter_by(
            user_id=user.id, status=GithubInstallationStatus.ACTIVE
        )
        .order_by(GithubInstallation.created_at.asc())
        .all()
    )


def _repository_from_payload(
    payload: dict[str, Any], installation_id: int
) -> GithubRepository:
    return GithubRepository(
        full_name=str(payload.get("full_name") or ""),
        default_branch=str(payload.get("default_branch") or "main"),
        private=bool(payload.get("private")),
        installation_id=int(installation_id),
    )


def list_repositories(user: User) -> list[GithubRepository]:
    _require_configured()
    installations = user_installations(user)
    if not installations:
        raise IntegrationNotConfigured(
            "No GitHub App installation is connected. Install the ServerPilot "
            "GitHub App and connect it from Connections first."
        )
    repositories: dict[str, GithubRepository] = {}
    for installation in installations:
        token = installation_token(installation.installation_id)
        page = 1
        while page <= 10:
            response = _github_request(
                "GET",
                f"/installation/repositories?per_page=100&page={page}",
                token=token,
            )
            payload = response.json() or {}
            items = payload.get("repositories") or []
            for item in items:
                repo = _repository_from_payload(item, installation.installation_id)
                if repo.full_name:
                    repositories[repo.full_name.lower()] = repo
            if len(items) < 100:
                break
            page += 1
    return sorted(repositories.values(), key=lambda repo: repo.full_name.lower())


def verify_repository(
    user: User, full_name: str
) -> tuple[GithubInstallation, GithubRepository]:
    _require_configured()
    normalized = (full_name or "").strip()
    if normalized.count("/") != 1 or any(
        not part or part.strip() != part for part in normalized.split("/")
    ):
        raise ValidationError("Repository must be in owner/name form.")
    installations = user_installations(user)
    if not installations:
        raise IntegrationNotConfigured(
            "Connect a GitHub App installation before selecting a repository."
        )
    for installation in installations:
        token = installation_token(installation.installation_id)
        try:
            response = _github_request(
                "GET",
                f"/repos/{normalized}",
                token=token,
                allowed=(200, 404),
            )
        except GithubAppError:
            continue
        if response.status_code == 404:
            continue
        payload = response.json() or {}
        if str(payload.get("full_name") or "").lower() != normalized.lower():
            continue
        return installation, _repository_from_payload(
            payload, installation.installation_id
        )
    raise ValidationError(
        "The selected repository is not accessible through your connected GitHub "
        "App installations."
    )


def verify_webhook_signature(body: bytes, signature_header: str | None) -> bool:
    secret = current_app.config.get("GITHUB_APP_WEBHOOK_SECRET")
    if not secret:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = (
        "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(expected, signature_header)


def oauth_access_token_for(user: User) -> str | None:
    """Return the linked GitHub OAuth app access token, refreshing if expired."""
    identity = _github_identity_for(user)
    if identity is None:
        return None
    return get_access_token(identity)


def oauth_repositories_for(user: User) -> list[GithubRepository]:
    """List repositories the linked GitHub account can read via the OAuth app.

    Used when the GitHub App is not configured; `installation_id` is 0 to mark
    the fallback source so callers never treat it as an App installation.
    """
    from .oauth import refresh_identity_token

    identity = _github_identity_for(user)
    if identity is None:
        raise PermissionDenied(
            "Link a GitHub account first, then repositories will load automatically."
        )
    token = get_access_token(identity)
    if (
        not token
        and identity.refresh_token_encrypted
        and refresh_identity_token(identity)
    ):
        token = get_access_token(identity, refresh=False)
    if not token:
        raise PermissionDenied(
            "Your GitHub authorization expired. Re-link GitHub from Connections."
        )
    repositories: dict[str, GithubRepository] = {}
    page = 1
    while page <= 10:
        response = _github_request(
            "GET",
            f"/user/repos?per_page=100&page={page}&sort=pushed",
            token=token,
            bearer_prefix="token",
            allowed=(200, 401, 422),
        )
        if response.status_code in {401, 422}:
            # Stale OAuth authorizations simply return no repositories.
            break
        items = response.json() or []
        for item in items if isinstance(items, list) else []:
            full_name = str(item.get("full_name") or "")
            if not full_name:
                continue
            repositories[full_name.lower()] = GithubRepository(
                full_name=full_name,
                default_branch=str(item.get("default_branch") or "main"),
                private=bool(item.get("private")),
                installation_id=0,
            )
        if len(items) < 100:
            break
        page += 1
    return sorted(repositories.values(), key=lambda repo: repo.full_name.lower())


def verify_repository_user_token(user: User, full_name: str) -> GithubRepository:
    """Verify a repository is readable with the linked GitHub OAuth token."""
    token = oauth_access_token_for(user)
    if not token:
        raise PermissionDenied(
            "Link a GitHub account with repository read access before selecting a repository."
        )
    normalized = (full_name or "").strip()
    if normalized.count("/") != 1 or any(
        not part or part.strip() != part for part in normalized.split("/")
    ):
        raise ValidationError("Repository must be in owner/name form.")
    response = _github_request(
        "GET",
        f"/repos/{normalized}",
        token=token,
        bearer_prefix="token",
        allowed=(200, 401, 403, 404),
    )
    if response.status_code != 200:
        raise ValidationError(
            "The repository is not accessible to your linked GitHub account."
        )
    payload = response.json() or {}
    return GithubRepository(
        full_name=str(payload.get("full_name") or normalized),
        default_branch=str(payload.get("default_branch") or "main"),
        private=bool(payload.get("private")),
        installation_id=0,
    )


def oauth_commit_for_ref(
    user: User, full_name: str, ref: str
) -> tuple[str, dict[str, Any]]:
    """Return the linked OAuth token plus commit metadata for a repository ref."""
    token = oauth_access_token_for(user)
    if not token:
        raise PermissionDenied(
            "Your GitHub authorization expired. Sign in with GitHub again."
        )
    return token, commit_metadata_for_ref(token, full_name, ref)


def commit_metadata_for_ref(token: str, full_name: str, ref: str) -> dict[str, Any]:
    normalized = (full_name or "").strip()
    normalized_ref = (ref or "main").strip()
    response = _github_request(
        "GET",
        f"/repos/{normalized}/commits/{quote(normalized_ref, safe='')}",
        token=token,
        bearer_prefix="token",
    )
    data = response.json()
    commit = data.get("commit") or {}
    if not data.get("sha"):
        raise GithubAppError("GitHub did not return a commit for that branch.")
    return {
        "sha": data["sha"],
        "message": (commit.get("message") or "")[:4000],
        "author": (
            (commit.get("author") or {}).get("name")
            or (data.get("author") or {}).get("login")
            or ""
        )[:255],
    }
