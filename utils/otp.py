import hashlib
import random
import time

from flask import current_app


def _hash_code(code: str) -> str:
    pepper = current_app.config["SECRET_KEY"]
    return hashlib.sha256(f"{pepper}:{code}".encode()).hexdigest()


def generate_otp():
    """Return (plaintext_code, code_hash, expires_at). The plaintext code is
    only used once, to send the email -- only the hash is persisted in the
    session for verification.
    """
    length = current_app.config["OTP_LENGTH"]
    code = "".join(str(random.randint(0, 9)) for _ in range(length))
    expires_at = time.time() + current_app.config["OTP_EXPIRY_SECONDS"]
    return code, _hash_code(code), expires_at


def verify_otp(submitted_code: str, code_hash: str, expires_at: float) -> bool:
    if not submitted_code or not code_hash or not expires_at:
        return False
    if time.time() > expires_at:
        return False
    return _hash_code(str(submitted_code).strip()) == code_hash
