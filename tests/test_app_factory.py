import logging

from app import create_app
from config import TestingConfig


def test_startup_logs_which_database_is_in_use(caplog):
    # TestingConfig pins SQLALCHEMY_DATABASE_URI to an in-memory sqlite regardless of the
    # environment, so a MySQL URL is set directly here -- the same field app.py reads.
    class Cfg(TestingConfig):
        SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:secret@db.example.com:3306/asm_system"

    with caplog.at_level(logging.INFO):
        create_app(Cfg)

    messages = [r.message for r in caplog.records]
    assert any(m.startswith("Database: ") and "db.example.com" in m and "asm_system" in m for m in messages)
    # the password must never end up in a log file
    assert not any("secret" in m for m in messages)


def test_a_missing_database_url_is_flagged_as_a_warning(caplog, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with caplog.at_level(logging.INFO):
        create_app(TestingConfig)

    warnings = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("DATABASE_URL is not set" in m for m in warnings)


def test_a_configured_database_url_gets_no_warning(caplog, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://root:secret@db.example.com:3306/asm_system")

    with caplog.at_level(logging.INFO):
        create_app(TestingConfig)

    warnings = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert not any("DATABASE_URL is not set" in m for m in warnings)
