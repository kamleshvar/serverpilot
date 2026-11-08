"""OAuth 2.0 / OpenID Connect provider integration (Google and GitHub)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, current_app, url_for

from ..errors import IntegrationNotConfigured
from ..extensions import db
from ..models import IdentityProvider, UserIdentity
from .encryption import get_encryption

logger = logging.getLogger(__name__)

GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com/"


class OAuthFlowError(RuntimeError):
    """Safe, user-facing OAuth failure (never carries secrets)."""


@dataclass(frozen=True)
class OAuthProfile:
    provider: IdentityProvider
    subject: str
    email: str | None
    email_verified: bool
    display_name: str
    login: str | None
    avatar_url: str | None
    access_token: str | None
    refresh_token: str | None
    expires_at: datetime | None
    scopes: str | None

    @property
    def provider_key(self) -> str:
        return self.provider.value


def init_oauth(app: Flask) -> OAuth | None:
    oauth = OAuth(app)
    registered = False
    if app.config.get("GOOGLE_OAUTH_ENABLED"):
        oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url=(
                "https://accounts.google.com/.well-known/openid-configuration"
            ),
            client_kwargs={
                "scope": "openid email profile",
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        registered = True
    if app.config.get("GITHUB_OAUTH_ENABLED"):
        oauth.register(
            name="github",
            client_id=app.config["GITHUB_CLIENT_ID"],
            client_secret=app.config["GITHUB_CLIENT_SECRET"],
            access_token_url=GITHUB_TOKEN_URL,
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url=GITHUB_API_URL,
            client_kwargs={
                "scope": "read:user user:email read:org",
                "token_endpoint_auth_method": "client_secret_post",
                "token_placement": "header",
            },
        )
        registered = True
    app.extensions["serverpilot_oauth"] = oauth if registered else None
    return oauth if registered else None


def _oauth_registry() -> OAuth:
    registry = current_app.extensions.get("serverpilot_oauth")
    if registry is None:
        raise IntegrationNotConfigured(
            "OAuth is not configured. Add provider client credentials to the "
            "backend environment."
        )
    return registry


def provider_enabled(provider: str | IdentityProvider) -> bool:
    key = provider.value if isinstance(provider, IdentityProvider) else provider
    registry = current_app.extensions.get("serverpilot_oauth")
    return bool(registry and key in registry._clients)


def get_oauth_client(provider: str | IdentityProvider):
    key = provider.value if isinstance(provider, IdentityProvider) else provider
    if key not in {"google", "github"}:
        raise IntegrationNotConfigured("Unsupported OAuth provider")
    registry = _oauth_registry()
    try:
        return getattr(registry, key)
    except AttributeError as exc:
        raise IntegrationNotConfigured(
            f"{key.title()} OAuth is not configured."
        ) from exc


def begin_authorize(provider: str, redirect_uri: str):
    client = get_oauth_client(provider)
    try:
        return client.authorize_redirect(redirect_uri)
    except Exception as exc:
        logger.exception("Failed to start %s OAuth flow", provider)
        raise OAuthFlowError("The authentication provider is not reachable.") from exc


def complete_authorize(provider: str, redirect_uri: str) -> OAuthProfile:
    client = get_oauth_client(provider)
    try:
        # authlib replays redirect_uri itself from the state data saved during
        # authorize_redirect (see BaseApp._format_state_params). Passing it
        # again raises TypeError ("got multiple values for keyword argument").
        token = client.authorize_access_token()
    except Exception as exc:
        # Authlib validates the state parameter inside this call. Never include
        # the exception text in the response because it may contain a token or
        # authorization code.
        logger.warning(
            "OAuth callback rejected for %s (%s)", provider, type(exc).__name__
        )
        raise OAuthFlowError(
            "The sign-in attempt could not be verified. Start sign-in again."
        ) from exc

    try:
        if provider == "google":
            return _google_profile(token)
        if provider == "github":
            return _github_profile(client, token)
    except OAuthFlowError:
        raise
    except Exception as exc:
        logger.warning(
            "OAuth profile retrieval failed for %s (%s)", provider, type(exc).__name__
        )
        raise OAuthFlowError(
            "Your identity could not be read from the authentication provider."
        ) from exc
    raise OAuthFlowError("Unsupported OAuth provider")


def _token_expiry(token: Any) -> datetime | None:
    expires_at = token.get("expires_at") if hasattr(token, "get") else None
    if expires_at is None:
        return None
    try:
        return datetime.fromtimestamp(float(expires_at), tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


def _google_profile(token) -> OAuthProfile:
    userinfo = token.get("userinfo")
    if not userinfo:
        client = get_oauth_client("google")
        response = client.get(GOOGLE_USERINFO_URL, token=token)
        if response.status_code != 200:
            raise OAuthFlowError("Google did not return an identity.")
        userinfo = response.json()
    subject = str(userinfo.get("sub") or "")
    email = (userinfo.get("email") or "").strip().lower() or None
    email_verified = bool(userinfo.get("email_verified"))
    if not subject:
        raise OAuthFlowError("Google did not return a stable account identifier.")
    if not email or not email_verified:
        raise OAuthFlowError(
            "Google did not provide a verified email address for this account."
        )
    return OAuthProfile(
        provider=IdentityProvider.GOOGLE,
        subject=subject,
        email=email,
        email_verified=email_verified,
        display_name=(userinfo.get("name") or email.split("@")[0])[:120],
        login=None,
        avatar_url=userinfo.get("picture"),
        access_token=token.get("access_token"),
        refresh_token=token.get("refresh_token"),
        expires_at=_token_expiry(token),
        scopes=token.get("scope"),
    )


def _github_profile(client, token) -> OAuthProfile:
    response = client.get("user", token=token)
    if response.status_code != 200:
        raise OAuthFlowError("GitHub did not return an identity.")
    data = response.json()
    subject = str(data.get("id") or "")
    if not subject:
        raise OAuthFlowError("GitHub did not return a stable account identifier.")

    email = (data.get("email") or "").strip().lower() or None
    verified = False
    if not email:
        emails = client.get("user/emails", token=token)
        if emails.status_code == 200:
            entries = emails.json() or []
            selected = next(
                (
                    item
                    for item in entries
                    if item.get("primary") and item.get("verified")
                ),
                None,
            ) or next((item for item in entries if item.get("verified")), None)
            if selected:
                email = (selected.get("email") or "").strip().lower() or None
                verified = bool(selected.get("verified"))
    else:
        # GitHub's /user email field is only returned for a verified address.
        verified = True

    return OAuthProfile(
        provider=IdentityProvider.GITHUB,
        subject=subject,
        email=email,
        email_verified=verified,
        display_name=(data.get("name") or data.get("login") or "GitHub user")[:120],
        login=data.get("login"),
        avatar_url=data.get("avatar_url"),
        access_token=token.get("access_token"),
        refresh_token=token.get("refresh_token"),
        expires_at=_token_expiry(token),
        scopes=token.get("scope"),
    )


def save_identity_tokens(identity: UserIdentity, profile: OAuthProfile) -> None:
    cipher = get_encryption()
    identity.access_token_encrypted = cipher.encrypt(profile.access_token)
    identity.refresh_token_encrypted = cipher.encrypt(profile.refresh_token)
    identity.token_expires_at = profile.expires_at
    identity.scopes = (profile.scopes or "")[:2000] or None
    identity.provider_email = profile.email or identity.provider_email
    identity.provider_login = profile.login or identity.provider_login
    identity.avatar_url = profile.avatar_url or identity.avatar_url
    identity.email_verified = profile.email_verified
    db.session.add(identity)


def get_access_token(identity: UserIdentity, *, refresh: bool = True) -> str | None:
    cipher = get_encryption()
    token = cipher.decrypt(identity.access_token_encrypted)
    if not token:
        return None
    expires = identity.token_expires_at
    if refresh and expires is not None and identity.refresh_token_encrypted:
        now = datetime.now(UTC)
        aware = expires if expires.tzinfo else expires.replace(tzinfo=UTC)
        if (aware - now).total_seconds() < 90:
            refreshed = refresh_identity_token(identity)
            if refreshed:
                token = refreshed
    return token


def refresh_identity_token(identity: UserIdentity) -> str | None:
    cipher = get_encryption()
    refresh_token = cipher.decrypt(identity.refresh_token_encrypted)
    if not refresh_token:
        return None
    provider = identity.provider.value
    if provider == "google":
        payload = {
            "client_id": current_app.config["GOOGLE_CLIENT_ID"],
            "client_secret": current_app.config["GOOGLE_CLIENT_SECRET"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        endpoint = GOOGLE_TOKEN_URL
    elif provider == "github":
        payload = {
            "client_id": current_app.config["GITHUB_CLIENT_ID"],
            "client_secret": current_app.config["GITHUB_CLIENT_SECRET"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        endpoint = GITHUB_TOKEN_URL
    else:
        return None
    try:
        response = requests.post(
            endpoint,
            data=payload,
            headers={"Accept": "application/json"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        logger.warning("OAuth refresh failed for provider=%s", provider)
        return None
    access_token = data.get("access_token")
    if not access_token:
        return None
    identity.access_token_encrypted = cipher.encrypt(access_token)
    if data.get("refresh_token"):
        identity.refresh_token_encrypted = cipher.encrypt(data["refresh_token"])
    if data.get("expires_in"):
        identity.token_expires_at = datetime.now(UTC).replace(microsecond=0)
        from datetime import timedelta

        identity.token_expires_at = datetime.now(UTC) + timedelta(
            seconds=int(data["expires_in"])
        )
    db.session.add(identity)
    db.session.commit()
    return access_token


def revoke_identity_tokens(identity: UserIdentity) -> None:
    cipher = get_encryption()
    token = cipher.decrypt(identity.access_token_encrypted)
    if not token:
        return
    if identity.provider == IdentityProvider.GOOGLE:
        try:
            requests.post(
                GOOGLE_REVOKE_URL,
                data={"token": token},
                timeout=10,
            )
        except requests.RequestException:
            logger.warning("Google token revocation request failed")
    # GitHub OAuth apps do not expose per-token revocation. Disconnecting the
    # identity locally removes stored credentials; the user can revoke the app
    # grant from GitHub settings.


def redirect_uri_for(provider: str) -> str:
    return current_app.config.get(f"{provider.upper()}_REDIRECT_URI") or url_for(
        "auth.oauth_callback", provider=provider, _external=True
    )
