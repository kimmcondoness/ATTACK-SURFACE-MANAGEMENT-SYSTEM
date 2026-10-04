"""Check that the verification-code email can actually be sent.

    python -m utils.mail_check                  # log in to the mail server and say what happens
    python -m utils.mail_check you@example.com  # ...and also send a test message there

Uses the same MAIL_* settings as the app (from .env), prints them without the password, and explains a
failure instead of just showing the exception. Exit status is 0 when everything works."""

import smtplib
import sys

from flask import Flask

from config import get_config
from utils.mailer import explain_failure, send_otp_email


def check_login(config) -> str:
    """Log in to the configured mail server (nothing is sent). Returns "" when it works, otherwise why not."""
    server, port = config["MAIL_SERVER"], config["MAIL_PORT"]
    username, password = config.get("MAIL_USERNAME"), config.get("MAIL_PASSWORD")
    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp:
            if config.get("MAIL_USE_TLS"):
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
    except (smtplib.SMTPException, OSError) as exc:
        return explain_failure(exc, server, bool(username and password))
    return ""


def main(argv) -> int:
    app = Flask("mail-check")
    app.config.from_object(get_config())
    config = app.config

    print(f"MAIL_SERVER   = {config.get('MAIL_SERVER') or '(not set)'}")
    print(f"MAIL_PORT     = {config['MAIL_PORT']}   TLS = {config.get('MAIL_USE_TLS')}")
    print(f"MAIL_USERNAME = {config.get('MAIL_USERNAME') or '(not set)'}")
    print(f"MAIL_PASSWORD = {'(set, %d characters)' % len(config['MAIL_PASSWORD']) if config.get('MAIL_PASSWORD') else '(not set)'}")
    print(f"MAIL_FROM     = {config['MAIL_FROM']}")

    if not config.get("MAIL_SERVER"):
        print("\nMAIL_SERVER is empty, so no email is ever sent: codes are only written to the server log.")
        print("Set MAIL_SERVER, MAIL_USERNAME and MAIL_PASSWORD in .env to turn email on.")
        return 1

    problem = check_login(config)
    if problem:
        print(f"\nFAILED to log in: {problem}")
        return 1
    print("\nLogin to the mail server works.")

    if len(argv) > 1:
        with app.app_context():
            sent = send_otp_email(argv[1], "123456", purpose="test")
        print(f"Test message to {argv[1]}: {'sent. Check the inbox (and spam).' if sent else 'NOT sent, see the log above.'}")
        return 0 if sent else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
