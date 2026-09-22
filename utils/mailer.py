import smtplib
from email.mime.text import MIMEText

from flask import current_app


def send_otp_email(to_email: str, code: str, purpose: str = "login") -> bool:
    """Send a one-time code by email (MFA login or password reset). If
    MAIL_SERVER is not configured, falls back to logging the code so the
    flow remains testable without real SMTP credentials.
    """
    mail_server = current_app.config.get("MAIL_SERVER")
    if not mail_server:
        current_app.logger.info("[DEV OTP] %s code for %s is %s (no MAIL_SERVER configured)", purpose, to_email, code)
        return False

    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    if not username or not password:
        current_app.logger.warning(
            "MAIL_SERVER is set to %s but MAIL_USERNAME/MAIL_PASSWORD are blank -- "
            "most providers (Gmail included) will reject an unauthenticated send. "
            "Set both in .env (Gmail requires a 16-character App Password, not your normal password).",
            mail_server,
        )

    message = MIMEText(f"Your Attack Surface Management {purpose} verification code is: {code}\n\nThis code expires in 1 minute.")
    message["Subject"] = f"Your ASM {purpose} verification code"
    message["From"] = current_app.config["MAIL_FROM"]
    message["To"] = to_email

    try:
        with smtplib.SMTP(mail_server, current_app.config["MAIL_PORT"], timeout=10) as smtp:
            if current_app.config.get("MAIL_USE_TLS"):
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.sendmail(current_app.config["MAIL_FROM"], [to_email], message.as_string())
    except (smtplib.SMTPException, OSError) as exc:
        # Surface the real failure reason (bad credentials, blocked port,
        # etc.) instead of letting the login flow 500 with no explanation,
        # and still log the code so the user isn't locked out mid-debug.
        current_app.logger.error("Failed to send OTP email to %s via %s: %s", to_email, mail_server, exc)
        current_app.logger.info("[FALLBACK OTP] %s code for %s is %s", purpose, to_email, code)
        return False
    return True
