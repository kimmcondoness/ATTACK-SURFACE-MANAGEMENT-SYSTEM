import pytest

import routes.auth_pages as auth_pages
from models import User
from tests.conftest import login
from utils.validators import ValidationError, password_problems, validate_password

_SIGNUP = {
    "first_name": "Sam", "last_name": "Analyst", "username": "sam.analyst", "email": "sam@example.com",
    "role": "cybersecurity_analyst", "captcha_answer": "0",
}

# password -> what the error message must mention
_WEAK = {
    "abcdefg1!": "an uppercase letter",
    "Abcdefgh!": "a number",
    "Abcdefg12": "a special character",
    "Abc1!xyz": "more than 8 characters",  # exactly 8 is not "more than 8"
    "password": "an uppercase letter, a number and a special character",
}


@pytest.mark.parametrize("password", ["Abcdef1!x", "A1!aaaaaa", "Sup3r-Secret pass", "ÉtéChaud9?"])
def test_valid_passwords_are_accepted(password):
    assert validate_password(password) == password
    assert password_problems(password) == []


@pytest.mark.parametrize("password,needle", _WEAK.items())
def test_weak_passwords_are_rejected_with_the_missing_rules(password, needle):
    with pytest.raises(ValidationError) as exc:
        validate_password(password)
    assert needle in str(exc.value)


def test_empty_password_is_rejected():
    with pytest.raises(ValidationError):
        validate_password("")


def _signup(client, monkeypatch, password):
    monkeypatch.setattr(auth_pages, "verify_captcha", lambda *args: True)
    monkeypatch.setattr(auth_pages, "_send_signup_otp", lambda email: None)
    return client.post("/signup", data={**_SIGNUP, "password": password, "confirm_password": password})


@pytest.mark.parametrize("password,needle", _WEAK.items())
def test_signup_refuses_a_weak_password(client, monkeypatch, password, needle):
    resp = _signup(client, monkeypatch, password)

    assert resp.status_code == 400
    assert needle in resp.get_data(as_text=True)
    with client.session_transaction() as session:
        assert "pending_signup" not in session


def test_signup_accepts_a_password_that_meets_every_rule(client, monkeypatch):
    assert _signup(client, monkeypatch, "Abcdef1!x").status_code == 302


def _start_reset(client, user):
    with client.session_transaction() as session:
        session["reset_verified"] = True
        session["reset_user_id"] = user.id


def test_reset_refuses_a_weak_password_and_keeps_the_old_one(client, analyst_user):
    _start_reset(client, analyst_user)

    resp = client.post("/reset-password", data={"password": "abcdefg1!", "confirm_password": "abcdefg1!"})

    assert resp.status_code == 400
    assert "an uppercase letter" in resp.get_data(as_text=True)
    assert User.query.get(analyst_user.id).check_password("AnalystPass123!")


def test_reset_accepts_a_strong_password(client, analyst_user):
    _start_reset(client, analyst_user)

    resp = client.post("/reset-password", data={"password": "NewPass#456x", "confirm_password": "NewPass#456x"})

    assert resp.status_code == 302
    assert User.query.get(analyst_user.id).check_password("NewPass#456x")


def test_admin_api_refuses_to_create_a_user_with_a_weak_password(client, admin_user):
    login(client, "admin", "AdminPass123!")

    resp = client.post("/api/users", json={"username": "weak", "email": "weak@example.com", "password": "password1", "role": "cybersecurity_analyst"})

    assert resp.status_code == 400
    assert "uppercase" in resp.get_json()["error"]
    assert User.query.filter_by(username="weak").first() is None


def test_admin_api_creates_a_user_with_a_strong_password(client, admin_user):
    login(client, "admin", "AdminPass123!")

    resp = client.post("/api/users", json={"username": "strong", "email": "strong@example.com", "password": "Strong#Pass1", "role": "cybersecurity_analyst"})

    assert resp.status_code == 201


def test_admin_api_refuses_to_set_a_weak_password_on_an_existing_user(client, admin_user, analyst_user):
    login(client, "admin", "AdminPass123!")

    resp = client.put(f"/api/users/{analyst_user.id}", json={"password": "weakweak"})

    assert resp.status_code == 400
    assert User.query.get(analyst_user.id).check_password("AnalystPass123!")


def test_signup_and_reset_pages_list_the_requirements_and_load_the_checklist_script(client, analyst_user):
    _start_reset(client, analyst_user)
    for path in ("/signup", "/reset-password"):
        html = client.get(path).get_data(as_text=True)
        assert 'id="password_rules"' in html, path
        for text in ("More than 8 characters", "uppercase letter", "one number", "special character"):
            assert text in html, (path, text)
        assert "js/password-rules.js" in html, path
        assert "At least 10 characters" not in html, path
