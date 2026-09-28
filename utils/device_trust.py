from datetime import datetime

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from flask import current_app

from utils.audit import latest_entry_time

# Audit actions that cancel every trusted-device cookie issued to a user before
# them (see services/user_admin_service.py). The audit entry's detail is exactly
# revocation_detail(user_id).
REVOKE_ACTIONS = ("mfa_reset", "password_reset_by_admin")


def revocation_detail(user_id: int) -> str:
    return f"target_user_id={user_id}"


COOKIE_NAME = "device_trust"
_SALT = "device-trust-cookie"


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=_SALT)


def issue_device_trust_token(user_id: int) -> str:
    return _serializer().dumps({"user_id": user_id})


def verify_device_trust_token(token, user_id: int) -> bool:
    if not token:
        return False
    max_age = current_app.config["DEVICE_TRUST_DAYS"] * 86400
    try:
        data, issued_at = _serializer().loads(token, max_age=max_age, return_timestamp=True)
    except (BadSignature, SignatureExpired):
        return False
    if data.get("user_id") != user_id:
        return False

    revoked_at = latest_entry_time(REVOKE_ACTIONS, detail=revocation_detail(user_id))
    if revoked_at is None:
        return True
    return issued_at.replace(tzinfo=None) > revoked_at


def set_device_trust_cookie(response, user_id: int):
    response.set_cookie(
        COOKIE_NAME,
        issue_device_trust_token(user_id),
        max_age=current_app.config["DEVICE_TRUST_DAYS"] * 86400,
        httponly=True,
        secure=current_app.config.get("SESSION_COOKIE_SECURE", False),
        samesite="Lax",
    )
    return response
