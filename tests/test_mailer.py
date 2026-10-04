import logging
import smtplib
import socket

import pytest

import routes.auth_pages as auth_pages
from extensions import db
from models import User
from utils import mail_check, mailer

NOT_SENT = "We could not send the verification email right now."


class FakeSMTP:
    """Stands in for smtplib.SMTP. Set `fail_at` to "login" or "connect" with `error` to make it fail there."""

    instances = []
    fail_at = None
    error = None

    def __init__(self, host, port, timeout=None):
        FakeSMTP.instances.append(self)
        self.host, self.port, self.sent, self.logged_in_as = host, port, [], None
        if FakeSMTP.fail_at == "connect":
            raise FakeSMTP.error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        pass

    def login(self, username, password):
        if FakeSMTP.fail_at == "login":
            raise FakeSMTP.error
        self.logged_in_as = (username, password)

    def sendmail(self, sender, recipients, text):
        self.sent.append((sender, recipients, text))


@pytest.fixture
def smtp(app, monkeypatch):
    """A mail server is configured (Gmail-style) and smtplib is replaced by FakeSMTP."""
    FakeSMTP.instances, FakeSMTP.fail_at, FakeSMTP.error = [], None, None
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    for key, value in {
        "MAIL_SERVER": "smtp.gmail.com", "MAIL_PORT": 587, "MAIL_USE_TLS": True,
        "MAIL_USERNAME": "noreply@example.com", "MAIL_PASSWORD": "abcdefghijklmnop", "MAIL_FROM": "noreply@example.com",
    }.items():
        monkeypatch.setitem(app.config, key, value)
    return FakeSMTP


def _rejected():
    return smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")


# ============================================================ sending
def test_a_code_is_emailed_when_the_mail_server_accepts_it(app, smtp):
    assert mailer.send_otp_email("user@example.com", "482913") is True

    [(sender, recipients, text)] = smtp.instances[0].sent
    assert (sender, recipients) == ("noreply@example.com", ["user@example.com"])
    assert "482913" in text and "verification code" in text
    assert smtp.instances[0].logged_in_as == ("noreply@example.com", "abcdefghijklmnop")


def test_without_a_mail_server_the_code_goes_to_the_log_and_nothing_is_sent(app, monkeypatch, caplog):
    monkeypatch.setitem(app.config, "MAIL_SERVER", None)
    with caplog.at_level(logging.INFO):
        assert mailer.send_otp_email("user@example.com", "111222") is False
    assert "[DEV OTP]" in caplog.text and "111222" in caplog.text


def test_a_rejected_app_password_is_explained_not_just_reported(app, smtp, caplog):
    smtp.fail_at, smtp.error = "login", _rejected()

    with caplog.at_level(logging.INFO):
        assert mailer.send_otp_email("user@example.com", "333444") is False

    assert "App Password" in caplog.text and "python -m utils.mail_check" in caplog.text
    assert "[FALLBACK OTP]" in caplog.text and "333444" in caplog.text                                 # the code is still recoverable from the log


def test_gmails_silent_disconnect_on_login_is_recognised_as_bad_credentials(app, smtp, caplog):
    """What smtplib reports when Gmail rejects the password: not a 535, just a closed connection."""
    smtp.fail_at, smtp.error = "login", smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
    with caplog.at_level(logging.INFO):
        assert mailer.send_otp_email("user@example.com", "555666") is False
    assert "App Password" in caplog.text and "Connection unexpectedly closed" in caplog.text


def test_an_unreachable_mail_server_points_at_the_network_not_the_password(app, smtp, caplog):
    smtp.fail_at, smtp.error = "connect", socket.gaierror("Name or service not known")
    with caplog.at_level(logging.INFO):
        assert mailer.send_otp_email("user@example.com", "777888") is False
    assert "could not reach smtp.gmail.com" in caplog.text and "App Password" not in caplog.text


def test_a_disconnect_with_no_credentials_configured_is_not_blamed_on_the_password(app, smtp, monkeypatch, caplog):
    monkeypatch.setitem(app.config, "MAIL_USERNAME", None)
    smtp.fail_at, smtp.error = "connect", smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
    with caplog.at_level(logging.INFO):
        mailer.send_otp_email("user@example.com", "999000")
    failure = next(r.getMessage() for r in caplog.records if r.levelno == logging.ERROR)
    assert "Connection unexpectedly closed" in failure and "did not accept" not in failure


def test_other_emails_use_the_same_delivery_and_never_raise(app, smtp):
    assert mailer.send_email("owner@example.com", "[ASM] change", "body") is True
    smtp.fail_at, smtp.error = "login", _rejected()
    assert mailer.send_email("owner@example.com", "[ASM] change", "body") is False


# ============================================================ the user is told when the email did not go out
@pytest.fixture
def mfa_user(app):
    user = User(username="mfa", email="mfa@example.com", role="cybersecurity_analyst")
    user.set_password("MfaPass#12345")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def no_captcha(monkeypatch):
    monkeypatch.setattr(auth_pages, "verify_captcha", lambda *args: True)


def _delivery(monkeypatch, sent):
    monkeypatch.setattr(auth_pages, "send_otp_email", lambda *args, **kwargs: sent)


def _sign_in(client):
    return client.post("/login", data={"username": "mfa", "password": "MfaPass#12345", "captcha_answer": "0"}, follow_redirects=True)


def test_signing_in_says_so_when_the_code_could_not_be_emailed(client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, False)

    html = _sign_in(client).get_data(as_text=True)

    assert NOT_SENT in html and "Resend code" in html and "Enter verification code" in html


def test_the_page_does_not_claim_an_email_it_did_not_send(client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, False)
    first = _sign_in(client).get_data(as_text=True)
    assert "We could not email a code to <strong>mfa@example.com</strong>." in first and "We emailed a 6-digit code" not in first

    reloaded = client.get("/login/verify").get_data(as_text=True)                                       # the flash is gone, the wording must not revert
    assert "We could not email a code" in reloaded and "We emailed a 6-digit code" not in reloaded


def test_the_page_says_a_code_was_emailed_when_it_was(client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, True)
    html = _sign_in(client).get_data(as_text=True)
    assert "We emailed a 6-digit code to <strong>mfa@example.com</strong>." in html and "We could not email" not in html


def test_signing_in_stays_quiet_when_the_email_went_out(client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, True)
    assert NOT_SENT not in _sign_in(client).get_data(as_text=True)


def test_the_development_hint_is_only_shown_in_debug_mode(app, client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, False)
    monkeypatch.setattr(app, "debug", False)
    production = _sign_in(client).get_data(as_text=True)
    assert NOT_SENT in production and "Development mode" not in production                            # never tell a production user where codes go

    client.get("/logout")
    monkeypatch.setattr(app, "debug", True)
    development = _sign_in(client).get_data(as_text=True)
    assert "Development mode: the code was written to the server console." in development


def test_a_failed_resend_does_not_claim_a_new_code_was_sent(client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, True)
    _sign_in(client)
    with client.session_transaction() as flask_session:
        flask_session["otp_last_sent_at"] = 0                                                           # the cooldown has passed

    _delivery(monkeypatch, False)
    html = client.post("/login/verify/resend", follow_redirects=True).get_data(as_text=True)

    assert NOT_SENT in html and "A new verification code has been sent." not in html


def test_a_successful_resend_still_confirms(client, mfa_user, no_captcha, monkeypatch):
    _delivery(monkeypatch, True)
    _sign_in(client)
    with client.session_transaction() as flask_session:
        flask_session["otp_last_sent_at"] = 0

    html = client.post("/login/verify/resend", follow_redirects=True).get_data(as_text=True)

    assert "A new verification code has been sent." in html and NOT_SENT not in html


def test_signing_up_says_so_when_the_code_could_not_be_emailed(client, no_captcha, monkeypatch):
    _delivery(monkeypatch, False)
    form = {"first_name": "Sam", "last_name": "Analyst", "username": "sam.analyst", "email": "sam@example.com", "role": "cybersecurity_analyst",
            "password": "StrongPass123!", "confirm_password": "StrongPass123!", "captcha_answer": "0"}

    html = client.post("/signup", data=form, follow_redirects=True).get_data(as_text=True)

    assert NOT_SENT in html and "Verify your email" in html


def test_a_password_reset_says_so_when_the_code_could_not_be_emailed(client, mfa_user, monkeypatch):
    _delivery(monkeypatch, False)

    html = client.post("/forgot-password", data={"email": "mfa@example.com"}, follow_redirects=True).get_data(as_text=True)

    assert NOT_SENT in html and "Verify it's you" in html


# ============================================================ python -m utils.mail_check
def test_the_check_reports_a_working_login(app, smtp):
    assert mail_check.check_login(app.config) == ""
    assert smtp.instances[0].logged_in_as == ("noreply@example.com", "abcdefghijklmnop")


def test_the_check_explains_a_rejected_login(app, smtp):
    smtp.fail_at, smtp.error = "login", _rejected()
    assert "App Password" in mail_check.check_login(app.config)


def _run_check(app, monkeypatch, argv=("mail_check",)):
    monkeypatch.setattr(mail_check, "get_config", lambda: type("Cfg", (), {key: app.config[key] for key in (
        "MAIL_SERVER", "MAIL_PORT", "MAIL_USE_TLS", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_FROM")}))
    return mail_check.main(list(argv))


def test_the_check_command_succeeds_and_can_send_a_test_message(app, smtp, monkeypatch, capsys):
    assert _run_check(app, monkeypatch) == 0
    assert _run_check(app, monkeypatch, ["mail_check", "me@example.com"]) == 0
    out = capsys.readouterr().out
    assert "Login to the mail server works." in out and "sent. Check the inbox" in out
    assert "abcdefghijklmnop" not in out and "(set, 16 characters)" in out                              # the password is never printed


def test_the_check_command_fails_loudly_on_a_bad_password(app, smtp, monkeypatch, capsys):
    smtp.fail_at, smtp.error = "login", _rejected()
    assert _run_check(app, monkeypatch) == 1
    assert "FAILED to log in" in capsys.readouterr().out


def test_the_check_command_says_when_email_is_switched_off(app, monkeypatch, capsys):
    monkeypatch.setitem(app.config, "MAIL_SERVER", None)
    assert _run_check(app, monkeypatch) == 1
    assert "no email is ever sent" in capsys.readouterr().out
