from __future__ import annotations

from serverpilot.extensions import db
from serverpilot.models import UserRole
from serverpilot.services.admin_auth import ADMIN_AUTH_AT_KEY, ADMIN_ID_KEY
from serverpilot.utils import utcnow
from tests.factories import make_user, make_website, sign_in


def _admin_session(client, app):
    with app.app_context():
        admin = make_user("admin@example.com", role=UserRole.ADMIN)
        make_website(admin)
        db.session.commit()
        admin_id = admin.id
    with client.session_transaction() as sess:
        sess[ADMIN_ID_KEY] = admin_id
        sess[ADMIN_AUTH_AT_KEY] = utcnow().isoformat()
        sess.permanent = True
    return admin_id


def test_admin_management_pages_render(client, app):
    _admin_session(client, app)

    for path in (
        "/techorigin/users",
        "/techorigin/sites",
        "/techorigin/domains",
        "/techorigin/backups",
    ):
        response = client.get(path)
        assert response.status_code == 200, path
        assert b"<!DOCTYPE html>" in response.data


def test_user_notifications_page_renders(client, app):
    with app.app_context():
        user = make_user("notify@example.com")
        db.session.commit()
        sign_in(client, user)

    response = client.get("/notifications")
    assert response.status_code == 200
    assert b"Account notifications" in response.data
