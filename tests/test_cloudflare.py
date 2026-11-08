from __future__ import annotations

from serverpilot.extensions import db
from serverpilot.models import DnsRecord, DnsStatus, Notification
from serverpilot.services.cloudflare import ensure_website_dns
from serverpilot.services.websites import _sync_cloudflare_website
from tests.factories import make_user, make_website


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload


def test_ensure_website_dns_creates_managed_cname(app, monkeypatch):
    app.config.update(
        CLOUDFLARE_API_TOKEN="test-token",
        CLOUDFLARE_TUNNEL_ID="tunnel-id",
        CLOUDFLARE_TUNNEL_CNAME=None,
    )
    responses = [
        FakeResponse(
            {
                "success": True,
                "result": [
                    {
                        "id": "zone-123",
                        "name": "techorigin.online",
                    }
                ],
            }
        ),
        FakeResponse(
            {
                "success": True,
                "result": {
                    "id": "record-123",
                    "content": "tunnel-id.cfargotunnel.com",
                },
            },
            status_code=200,
        ),
    ]

    def fake_request(method, url, **kwargs):
        assert method in {"GET", "POST"}
        return responses.pop(0)

    monkeypatch.setattr(
        "serverpilot.services.cloudflare.requests.request", fake_request
    )

    with app.app_context():
        user = make_user("dns@example.com")
        website = make_website(user)
        db.session.commit()
        record = ensure_website_dns(website, commit=True)
        assert record.cloudflare_record_id == "record-123"
        assert record.status == DnsStatus.VALID
        assert record.content == "tunnel-id.cfargotunnel.com"
        assert DnsRecord.query.count() == 1


def test_missing_tunnel_is_reported_without_breaking_website_sync(app):
    app.config.update(
        CLOUDFLARE_API_TOKEN="test-token",
        CLOUDFLARE_TUNNEL_ID=None,
        CLOUDFLARE_TUNNEL_CNAME=None,
    )
    with app.app_context():
        user = make_user("tunnel@example.com")
        website = make_website(user)
        db.session.commit()

        _sync_cloudflare_website(website)

        assert DnsRecord.query.count() == 0
        assert (
            Notification.query.filter_by(category="cloudflare_sync_failed").count() == 1
        )
