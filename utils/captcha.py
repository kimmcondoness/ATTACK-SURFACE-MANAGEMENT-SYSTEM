import hashlib
import random
import time

from flask import current_app


def _hash_answer(answer: str) -> str:
    pepper = current_app.config["SECRET_KEY"]
    return hashlib.sha256(f"{pepper}:{answer.strip().lower()}".encode()).hexdigest()


def generate_captcha():
    """Return (question, answer_hash, expires_at). The plaintext answer is
    never returned to the caller -- only its hash is kept (in the session),
    so a user reading their own session cookie can't trivially bypass it.
    """
    a, b = random.randint(1, 20), random.randint(1, 20)
    op = random.choice(["+", "-"])
    if op == "-" and b > a:
        a, b = b, a
    answer = a + b if op == "+" else a - b
    question = f"{a} {op} {b} = ?"
    expires_at = time.time() + current_app.config["CAPTCHA_EXPIRY_SECONDS"]
    return question, _hash_answer(str(answer)), expires_at


def verify_captcha(submitted_answer: str, answer_hash: str, expires_at: float) -> bool:
    if not submitted_answer or not answer_hash or not expires_at:
        return False
    if time.time() > expires_at:
        return False
    return _hash_answer(str(submitted_answer)) == answer_hash
