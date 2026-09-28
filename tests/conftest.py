import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from flask import g

from app import create_app
from config import TestingConfig
from extensions import db as _db
from models import ROLE_ANALYST, ROLE_IT_ADMIN, User


@pytest.fixture
def app():
    application = create_app(TestingConfig)

    @application.before_request
    def _forget_cached_login():
        # The tests share one long-lived app context, so Flask-Login's per-request
        # user cache would otherwise leak from one test client to the next.
        g.pop("_login_user", None)

    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(app):
    user = User(username="admin", email="admin@example.com", role=ROLE_IT_ADMIN)
    user.set_password("AdminPass123!")
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture
def analyst_user(app):
    user = User(username="analyst", email="analyst@example.com", role=ROLE_ANALYST)
    user.set_password("AnalystPass123!")
    _db.session.add(user)
    _db.session.commit()
    return user


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})
