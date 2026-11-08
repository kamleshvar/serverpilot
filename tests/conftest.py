from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

from serverpilot import create_app
from serverpilot.extensions import db as _db
from serverpilot.services.domains import seed_configured_domains
from serverpilot.services.settings import seed_default_settings


@event.listens_for(Engine, "connect")
def _sqlite_foreign_keys(dbapi_connection, _connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


@pytest.fixture()
def app():
    application = create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "SQLALCHEMY_ENGINE_OPTIONS": {
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            },
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": False,
            "SERVER_NAME": "localhost",
            "LOG_LEVEL": "ERROR",
        },
    )
    with application.app_context():
        _db.create_all()
        seed_configured_domains()
        seed_default_settings()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    return _db
