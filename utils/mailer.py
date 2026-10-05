import smtplib
import socket
from email.mime.text import MIMEText

from flask import current_app


def explain_failure(exc: Exception, mail_server: str, has_credentials: bool) -> str:
    """Say what a failed send most likely means, in words someone can act on.

    A wrong or revoked Gmail App Password is the usual culprit, and it does not always look like one:
    Gmail answers 535 (BadCredentials), but Python's smtplib often reports the same thing as
    "Connection unexpectedly closed", which sends people looking at the network instead."""
    if isinstance(exc, smtplib.SMTPAuthenticationError) or (
        isinstance(exc, smtplib.SMTPServerDisconnected) and has_credentials
    ):
        return (
            f"{mail_server} did not accept MAIL_USERNAME/MAIL_PASSWORD ({exc}). For Gmail, MAIL_PASSWORD must be a "
            "16-character App Password (Google Account > Security > 2-Step Verification > App passwords), not the "
            "account password; create a new one if it was revoked, then restart the app. "
            "Check with: python -m utils.mail_check"
        )
    if isinstance(exc, (smtplib.SMTPConnectError, ConnectionError, TimeoutError, socket.gaierror)):
        return f"could not reach {mail_server} ({exc}). Check MAIL_SERVER/MAIL_PORT and that outbound SMTP is not blocked."
    return str(exc)


def _deliver(message: MIMEText, to_email: str) -> bool:
    """Send `message` through the configured SMTP server. Never raises; logs why when it fails."""
    config = current_app.config
    mail_server = config["MAIL_SERVER"]
    username = config.get("MAIL_USERNAME")
    password = config.get("MAIL_PASSWORD")
    if not username or not password:
        current_app.logger.warning(
            "MAIL_SERVER is set to %s but MAIL_USERNAME/MAIL_PASSWORD are blank -- "
            "most providers (Gmail included) will reject an unauthenticated send. "
            "Set both in .env (Gmail requires a 16-character App Password, not your normal password).",
            mail_server,
        )

    message["From"] = config["MAIL_FROM"]
    message["To"] = to_email
    try:
        with smtplib.SMTP(mail_server, config["MAIL_PORT"], timeout=10) as smtp:
            if config.get("MAIL_USE_TLS"):
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.sendmail(config["MAIL_FROM"], [to_email], message.as_string())
    except (smtplib.SMTPException, OSError) as exc:
        current_app.logger.error(
            "Failed to send email to %s via %s: %s", to_email, mail_server, explain_failure(exc, mail_server, bool(username and password))
        )
        return False
    return True


def send_otp_email(to_email: str, code: str, purpose: str = "login") -> bool:
    """Send a one-time code by email (MFA login or password reset). Returns whether it was sent.

    If MAIL_SERVER is not configured, or the send fails, the code is written to the server log instead
    so the flow remains testable without real SMTP credentials (and the caller tells the user the
    email did not go out, so they are not left waiting for one).
    """
    if not current_app.config.get("MAIL_SERVER"):
        current_app.logger.info("[DEV OTP] %s code for %s is %s (no MAIL_SERVER configured)", purpose, to_email, code)
        return False

    message = MIMEText(f"Your Attack Surface Management {purpose} verification code is: {code}\n\nThis code expires in 1 minute.")
    message["Subject"] = f"Your ASM {purpose} verification code"
    if _deliver(message, to_email):
        return True
    # Still log the code so the user isn't locked out mid-debug.
    current_app.logger.info("[FALLBACK OTP] %s code for %s is %s", purpose, to_email, code)
    return False


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send a plain-text email. Without a configured MAIL_SERVER the message is only logged,
    so monitoring alerts stay testable without SMTP credentials. Never raises."""
    if not current_app.config.get("MAIL_SERVER"):
        current_app.logger.info("[DEV EMAIL] to %s | %s\n%s", to_email, subject, body)
        return False

    message = MIMEText(body)
    message["Subject"] = subject
    return _deliver(message, to_email)
