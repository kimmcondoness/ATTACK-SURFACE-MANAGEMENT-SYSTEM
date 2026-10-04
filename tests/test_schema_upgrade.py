import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from sqlalchemy import inspect

from app import create_app
from config import TestingConfig
from database.upgrade import COLUMN_UPGRADES, upgrade_schema
from extensions import db

OLD_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY, username VARCHAR(80) NOT NULL, email VARCHAR(120) NOT NULL, first_name VARCHAR(80),
    last_name VARCHAR(80), password_hash VARCHAR(128) NOT NULL, role VARCHAR(30) NOT NULL,
    is_active_flag BOOLEAN NOT NULL DEFAULT 1, created_at DATETIME);
CREATE TABLE authorized_targets (
    id INTEGER PRIMARY KEY, domain VARCHAR(255) NOT NULL, description VARCHAR(255),
    authorized BOOLEAN NOT NULL DEFAULT 0, owner_id INTEGER NOT NULL, created_at DATETIME);
CREATE TABLE assets (
    id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, subdomain VARCHAR(255), ip_address VARCHAR(45),
    url VARCHAR(500), technologies VARCHAR(500), discovery_date DATETIME);
INSERT INTO users (id, username, email, password_hash, role) VALUES (1, 'analyst', 'a@example.com', 'x', 'cybersecurity_analyst');
INSERT INTO authorized_targets (id, domain, authorized, owner_id) VALUES (1, 'example.com', 1, 1);
INSERT INTO assets (id, target_id, subdomain, url) VALUES (1, 1, 'www.example.com', 'https://www.example.com');
"""


@pytest.fixture
def old_database(tmp_path):
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.executescript(OLD_SCHEMA)
    connection.commit()
    connection.close()

    class Config(TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{path}"
        AUTO_UPGRADE_SCHEMA = True

    return Config, path


def _columns(table):
    return {c["name"] for c in inspect(db.engine).get_columns(table)}


def test_an_old_database_gets_the_new_columns_and_table_without_losing_rows(old_database):
    config, _ = old_database
    app = create_app(config)

    with app.app_context():
        assert {"monitor_interval_days", "monitor_last_run_at"} <= _columns("authorized_targets")
        assert {"last_seen_at", "status", "missed_runs"} <= _columns("assets")
        assert {"monitor_events", "monitor_runs", "monitor_heartbeat", "report_shares"} <= set(inspect(db.engine).get_table_names())
        assert "last_seen_at" in _columns("users")

        user = db.session.execute(db.text("SELECT username, last_seen_at FROM users")).one()
        assert tuple(user) == ("analyst", None)                        # existing users are kept, nobody is "seen" yet
        row = db.session.execute(db.text("SELECT domain, monitor_interval_days FROM authorized_targets")).one()
        assert tuple(row) == ("example.com", None)                     # monitoring starts off for existing targets
        asset = db.session.execute(db.text("SELECT subdomain, status, missed_runs FROM assets")).one()
        assert tuple(asset) == ("www.example.com", "active", 0)        # existing assets count as active


def test_the_upgrade_is_safe_to_repeat(old_database):
    config, _ = old_database
    app = create_app(config)

    with app.app_context():
        assert upgrade_schema(db) == []
        assert upgrade_schema(db) == []


def test_it_reports_what_it_changed(old_database):
    config, path = old_database

    class Manual(config):
        AUTO_UPGRADE_SCHEMA = False

    app = create_app(Manual)
    with app.app_context():
        applied = upgrade_schema(db)
        assert {"created table monitor_events", "created table monitor_runs", "created table report_shares"} <= set(applied)
        assert {f"added {t}.{c}" for t, c, _ in COLUMN_UPGRADES} <= set(applied)


def test_a_brand_new_database_is_left_to_create_all(tmp_path):
    class Config(TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'fresh.db'}"

    app = create_app(Config)
    with app.app_context():
        assert upgrade_schema(db) == []
        db.create_all()
        assert {"monitor_interval_days"} <= _columns("authorized_targets")


def test_the_upgrade_works_when_the_app_starts_in_a_fresh_process(old_database):
    """At start-up nothing has imported the models yet, which is exactly when the upgrade runs.
    Inside the test run they are already imported, so only a fresh process tells the truth."""
    _, path = old_database
    snippet = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, ".")
        from config import TestingConfig
        class Cfg(TestingConfig):
            SQLALCHEMY_DATABASE_URI = "sqlite:///{Path(path).as_posix()}"
            AUTO_UPGRADE_SCHEMA = True
        from app import create_app
        from extensions import db
        from sqlalchemy import inspect
        app = create_app(Cfg)
        with app.app_context():
            print("TABLES", sorted(inspect(db.engine).get_table_names()))
            print("ASSET_COLUMNS", sorted(c["name"] for c in inspect(db.engine).get_columns("assets")))
    """)
    root = Path(__file__).resolve().parent.parent
    out = subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True, cwd=root, timeout=120)

    assert out.returncode == 0, out.stderr[-800:]
    assert "monitor_events" in out.stdout
    assert "missed_runs" in out.stdout and "last_seen_at" in out.stdout
