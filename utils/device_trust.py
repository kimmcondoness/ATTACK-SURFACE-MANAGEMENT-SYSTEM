from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from flask import current_app

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
        data = _serializer().loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return False
    return data.get("user_id") == user_id


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
