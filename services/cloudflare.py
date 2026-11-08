"""Cloudflare zone and DNS synchronization for managed domains."""

from __future__ import annotations

import logging
from typing import Any

import requests
from flask import current_app

from ..errors import AppError, IntegrationNotConfigured, ValidationError
from ..extensions import db
from ..models import (
    DnsRecord,
    DnsRecordType,
    DnsStatus,
    Domain,
    DomainStatus,
    Website,
    WebsiteStatus,
)
from ..utils import utcnow

logger = logging.getLogger(__name__)

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
REQUEST_TIMEOUT = (5, 20)
USER_AGENT = "ServerPilot/1.0"


class CloudflareError(AppError):
    status_code = 502
    code = "cloudflare_error"
    default_message = "Cloudflare could not complete the DNS request."


def cloudflare_configured() -> bool:
    return bool(current_app.config.get("CLOUDFLARE_API_TOKEN"))


def _require_configured() -> None:
    if not cloudflare_configured():
        raise IntegrationNotConfigured(
            "Cloudflare is not configured. Set CLOUDFLARE_API_TOKEN and the "
            "tunnel DNS target before synchronizing DNS."
        )


def tunnel_cname_target() -> str:
    explicit = str(current_app.config.get("CLOUDFLARE_TUNNEL_CNAME") or "").strip()
    if explicit:
        return explicit.rstrip(".")
    tunnel_id = str(current_app.config.get("CLOUDFLARE_TUNNEL_ID") or "").strip()
    if not tunnel_id:
        raise IntegrationNotConfigured(
            "Set CLOUDFLARE_TUNNEL_CNAME or CLOUDFLARE_TUNNEL_ID before "
            "synchronizing website DNS records."
        )
    return f"{tunnel_id}.cfargotunnel.com"


def _api_request(
    method: str,
    path: str,
    *,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    allowed: tuple[int, ...] = (200,),
) -> dict[str, Any]:
    _require_configured()
    token = str(current_app.config.get("CLOUDFLARE_API_TOKEN") or "")
    try:
        response = requests.request(
            method,
            f"{CLOUDFLARE_API}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            json=json,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("Cloudflare request failed method=%s path=%s", method, path)
        raise CloudflareError("Cloudflare could not be reached.") from exc
    if response.status_code not in allowed:
        logger.warning(
            "Cloudflare rejected method=%s path=%s status=%s",
            method,
            path,
            response.status_code,
        )
        raise CloudflareError(
            f"Cloudflare rejected the DNS request (HTTP {response.status_code})."
        )
    if response.status_code == 404:
        return {"success": True, "result": None}
    try:
        payload = response.json()
    except ValueError as exc:
        raise CloudflareError("Cloudflare returned an invalid response.") from exc
    if not isinstance(payload, dict) or payload.get("success") is not True:
        errors = payload.get("errors") if isinstance(payload, dict) else None
        message = "Cloudflare rejected the DNS request."
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict) and first.get("message"):
                message = str(first["message"])[:500]
        raise CloudflareError(message)
    return payload


def resolve_zone(domain: Domain) -> str:
    if domain.cloudflare_zone_id:
        return domain.cloudflare_zone_id
    payload = _api_request(
        "GET",
        "/zones",
        params={"name": domain.name, "status": "active", "per_page": 50},
    )
    result = payload.get("result") or []
    for item in result:
        if not isinstance(item, dict):
            continue
        if str(item.get("name") or "").lower() == domain.name.lower() and item.get(
            "id"
        ):
            domain.cloudflare_zone_id = str(item["id"])[:64]
            domain.cloudflare_zone_name = domain.name
            if domain.status == DomainStatus.PENDING:
                domain.status = DomainStatus.ACTIVE
            db.session.add(domain)
            return domain.cloudflare_zone_id
    raise CloudflareError(
        f"Cloudflare zone {domain.name} was not found or is not active for this token."
    )


def _record_name(fqdn: str) -> str:
    return (fqdn or "").strip().lower().rstrip(".")


def _desired_payload(fqdn: str, target: str) -> dict[str, Any]:
    return {
        "type": DnsRecordType.CNAME.value,
        "name": _record_name(fqdn),
        "content": target,
        "ttl": int(current_app.config.get("CLOUDFLARE_DNS_TTL", 1)),
        "proxied": bool(current_app.config.get("CLOUDFLARE_PROXIED", True)),
    }


def ensure_website_dns(website: Website, *, commit: bool = False) -> DnsRecord | None:
    """Create or update the CNAME that routes a website through the tunnel."""
    if not cloudflare_configured():
        return None
    domain = website.domain
    if domain is None:
        raise ValidationError("The website domain is missing.")
    target = tunnel_cname_target()
    zone_id = resolve_zone(domain)
    payload = _desired_payload(website.fqdn, target)
    record = DnsRecord.query.filter_by(
        domain_id=domain.id,
        name=payload["name"],
        record_type=DnsRecordType.CNAME,
    ).one_or_none()
    if record is None:
        record = DnsRecord(
            domain_id=domain.id,
            website_id=website.id,
            record_type=DnsRecordType.CNAME,
            name=payload["name"],
            content=target,
            ttl=payload["ttl"],
            proxied=payload["proxied"],
            managed_by_platform=True,
            status=DnsStatus.PENDING,
            created_by_id=website.owner_id,
        )
        db.session.add(record)
    if record.cloudflare_record_id:
        response = _api_request(
            "PATCH",
            f"/zones/{zone_id}/dns_records/{record.cloudflare_record_id}",
            json=payload,
        )
    else:
        response = _api_request("POST", f"/zones/{zone_id}/dns_records", json=payload)
    result = response.get("result") or {}
    if not isinstance(result, dict) or not result.get("id"):
        raise CloudflareError("Cloudflare did not return a DNS record identifier.")
    record.cloudflare_record_id = str(result["id"])[:64]
    record.website_id = website.id
    record.content = target
    record.ttl = payload["ttl"]
    record.proxied = payload["proxied"]
    record.managed_by_platform = True
    record.status = DnsStatus.VALID
    record.last_checked_at = utcnow()
    record.last_error = None
    domain.dns_status = DnsStatus.VALID
    domain.last_dns_check_at = utcnow()
    domain.dns_last_error = None
    db.session.add(record)
    db.session.add(domain)
    if commit:
        db.session.commit()
    return record


def delete_dns_record(domain: Domain, name: str, *, commit: bool = False) -> bool:
    record = DnsRecord.query.filter_by(
        domain_id=domain.id,
        name=_record_name(name),
        record_type=DnsRecordType.CNAME,
    ).one_or_none()
    if record is None:
        return False
    if not record.cloudflare_record_id:
        db.session.delete(record)
        if commit:
            db.session.commit()
        return True
    if not cloudflare_configured():
        raise IntegrationNotConfigured("Cloudflare is not configured.")
    zone_id = resolve_zone(domain)
    _api_request(
        "DELETE",
        f"/zones/{zone_id}/dns_records/{record.cloudflare_record_id}",
        allowed=(200, 404),
    )
    db.session.delete(record)
    if commit:
        db.session.commit()
    return True


def check_website_dns(website: Website, *, commit: bool = False) -> list[DnsRecord]:
    if not cloudflare_configured():
        return []
    target = tunnel_cname_target()
    records = list(website.dns_records)
    for record in records:
        if not record.cloudflare_record_id:
            record.status = DnsStatus.MISSING
            record.last_error = "No Cloudflare record identifier is stored."
            record.last_checked_at = utcnow()
            continue
        zone_id = resolve_zone(record.domain)
        try:
            response = _api_request(
                "GET",
                f"/zones/{zone_id}/dns_records/{record.cloudflare_record_id}",
                allowed=(200, 404),
            )
        except CloudflareError as exc:
            record.status = DnsStatus.ERROR
            record.last_error = exc.message[:4000]
            record.last_checked_at = utcnow()
            continue
        result = response.get("result")
        if not isinstance(result, dict):
            record.status = DnsStatus.MISSING
            record.last_error = "The Cloudflare DNS record no longer exists."
            record.last_checked_at = utcnow()
            continue
        actual = str(result.get("content") or "").rstrip(".").lower()
        record.status = (
            DnsStatus.VALID if actual == target.lower() else DnsStatus.CONFLICT
        )
        record.last_error = (
            None
            if record.status == DnsStatus.VALID
            else f"Expected {target}, found {actual or 'nothing'}."
        )
        record.last_checked_at = utcnow()
        record.content = actual or record.content
    if records:
        website.domain.dns_status = (
            DnsStatus.VALID
            if all(record.status == DnsStatus.VALID for record in records)
            else DnsStatus.ERROR
        )
        website.domain.last_dns_check_at = utcnow()
        db.session.add(website.domain)
    if commit:
        db.session.commit()
    return records


def sync_domains() -> list[Domain]:
    """Resolve and store Cloudflare zone IDs for all configured domains."""
    if not cloudflare_configured():
        raise IntegrationNotConfigured("Cloudflare is not configured.")
    domains = Domain.query.filter(Domain.name.in_(current_app.config["DOMAINS"])).all()
    for domain in domains:
        resolve_zone(domain)
    db.session.commit()
    return domains


def sync_all_website_dns() -> int:
    if not cloudflare_configured():
        raise IntegrationNotConfigured("Cloudflare is not configured.")
    websites = Website.query.filter(
        Website.status != WebsiteStatus.DELETED,
        Website.deleted_at.is_(None),
    ).all()
    for website in websites:
        ensure_website_dns(website)
    db.session.commit()
    return len(websites)
