import time

import pytest

import routes.auth_pages as auth_pages
from extensions import db
from models import User
from utils.device_trust import COOKIE_NAME, issue_device_trust_token

WEEK = 7 * 86400


@pytest.fixture
def mfa_user(app):
    user = User(username="mfa", email="mfa@example.com", role="cybersecurity_analyst")
    user.set_password("MfaPass#12345")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def codes(monkeypatch):
    """Skip the CAPTCHA, never send a real email, and remember the code that was 'emailed'."""
    sent = []
    real_generate = auth_pages.generate_otp

    def generate():
        code, code_hash, expires = real_generate()
        sent.append(code)
        return code, code_hash, expires

    monkeypatch.setattr(auth_pages, "verify_captcha", lambda *args: True)
    monkeypatch.setattr(auth_pages, "generate_otp", generate)
    monkeypatch.setattr(auth_pages, "send_otp_email", lambda *args, **kwargs: True)
    return sent


def _sign_in(client):
    return client.post("/login", data={"username": "mfa", "password": "MfaPass#12345", "captcha_answer": "0"})


def _enter_code(client, code):
    return client.post("/login/verify", data={"otp_code": code})


def _token_issued_days_ago(user_id, days):
    real = time.time
    time.time = lambda: real() - days * 86400
    try:
        return issue_device_trust_token(user_id)
    finally:
        time.time = real


def _cookie_header(response):
    return [h for h in response.headers.getlist("Set-Cookie") if h.startswith(COOKIE_NAME + "=")]


def test_the_trust_window_is_one_week():
    from config import Config

    assert Config.DEVICE_TRUST_DAYS == 7


def test_first_sign_in_needs_the_code_and_then_trusts_the_browser_for_a_week(client, mfa_user, codes):
    resp = _sign_in(client)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login/verify")
    assert len(codes) == 1

    verified = _enter_code(client, codes[0])

    assert verified.status_code == 302 and verified.headers["Location"].endswith("/dashboard")
    cookie = _cookie_header(verified)
    assert cookie and f"Max-Age={WEEK}" in cookie[0]


def test_signing_out_and_back_in_within_the_week_needs_no_code(client, mfa_user, codes):
    _sign_in(client)
    _enter_code(client, codes[0])

    client.post("/logout")
    again = _sign_in(client)

    assert again.status_code == 302 and again.headers["Location"].endswith("/dashboard")
    assert len(codes) == 1  # no second code was generated or "emailed"


def test_signing_in_again_does_not_extend_the_week(client, mfa_user, codes):
    _sign_in(client)
    _enter_code(client, codes[0])
    client.post("/logout")

    trusted_sign_in = _sign_in(client)

    assert trusted_sign_in.status_code == 302
    assert _cookie_header(trusted_sign_in) == []  # the cookie is left alone, so it still expires a week after the code


def test_a_device_verified_six_days_ago_is_still_trusted(client, mfa_user, codes):
    client.set_cookie(COOKIE_NAME, _token_issued_days_ago(mfa_user.id, 6))

    resp = _sign_in(client)

    assert resp.headers["Location"].endswith("/dashboard") and codes == []


def test_a_device_verified_eight_days_ago_must_enter_a_code_again(client, mfa_user, codes):
    client.set_cookie(COOKIE_NAME, _token_issued_days_ago(mfa_user.id, 8))

    resp = _sign_in(client)

    assert resp.headers["Location"].endswith("/login/verify") and len(codes) == 1

    renewed = _enter_code(client, codes[0])
    assert f"Max-Age={WEEK}" in _cookie_header(renewed)[0]  # a fresh week starts from this code


def test_a_trusted_browser_of_one_user_does_not_skip_another_users_code(client, mfa_user, codes):
    other = User(username="other", email="other@example.com", role="cybersecurity_analyst")
    other.set_password("OtherPass#12345")
    db.session.add(other)
    db.session.commit()
    client.set_cookie(COOKIE_NAME, issue_device_trust_token(other.id))

    resp = _sign_in(client)  # signing in as mfa on other's trusted browser

    assert resp.headers["Location"].endswith("/login/verify") and len(codes) == 1


def test_a_browser_without_the_cookie_is_asked_for_the_code(client, mfa_user, codes):
    resp = _sign_in(client)
    assert resp.headers["Location"].endswith("/login/verify")


def test_the_code_page_tells_the_user_they_will_not_be_asked_again_for_a_week(client, mfa_user, codes):
    _sign_in(client)

    html = client.get("/login/verify").get_data(as_text=True)

    assert "for 7 days" in html
