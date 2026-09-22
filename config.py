import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'asm.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

    SCANNER_TIMEOUT_SECONDS = 60

    # Login security controls
    CAPTCHA_EXPIRY_SECONDS = 5 * 60
    OTP_EXPIRY_SECONDS = 1 * 60
    OTP_LENGTH = 6
    OTP_MAX_ATTEMPTS = 5

    # How long a "this device already completed MFA" cookie stays valid, so
    # frequent sign-ins from the same browser aren't re-prompted for an OTP
    # every time. Password + CAPTCHA are still required on every sign-in.
    DEVICE_TRUST_DAYS = 30

    # Rate limiting (per-IP). In-memory storage is fine for a single-process
    # dev/small deployment; swap for Redis (RATELIMIT_STORAGE_URI=redis://...)
    # if this ever runs behind multiple worker processes.
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"

    # Email (MFA one-time code) settings. If MAIL_SERVER is not set, the
    # mailer falls back to logging the OTP instead of sending it, so the
    # login flow stays testable without SMTP credentials configured.
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    # Gmail (and most providers) reject or spam-flag mail whose From address
    # doesn't match the authenticated account, so default From to the sending
    # account instead of the placeholder domain unless explicitly overridden.
    MAIL_FROM = os.environ.get("MAIL_FROM") or os.environ.get("MAIL_USERNAME") or "no-reply@asm-system.local"


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return config_by_name.get(env, DevelopmentConfig)
