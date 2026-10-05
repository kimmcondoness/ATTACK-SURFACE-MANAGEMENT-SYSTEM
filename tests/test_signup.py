import routes.auth_pages as auth_pages
from models import User

_FORM = {
    "first_name": "Sam",
    "last_name": "Analyst",
    "username": "sam.analyst",
    "email": "sam@example.com",
    "password": "StrongPass123!",
    "confirm_password": "StrongPass123!",
    "captcha_answer": "0",
}


def _post_signup(client, monkeypatch, **overrides):
    monkeypatch.setattr(auth_pages, "verify_captcha", lambda *args: True)
    monkeypatch.setattr(auth_pages, "_send_signup_otp", lambda email: None)
    return client.post("/signup", data={**_FORM, **overrides})


def test_signup_page_has_no_account_type_choice_and_no_admin_option(client):
    html = client.get("/signup").get_data(as_text=True)

    assert "Account type" not in html
    assert "it_admin" not in html
    assert 'value="cybersecurity_analyst"' in html
    assert 'value="threat_intel_analyst"' in html


def test_signup_rejects_an_admin_role_even_if_the_form_is_tampered_with(client, monkeypatch):
    resp = _post_signup(client, monkeypatch, role="it_admin")

    assert resp.status_code == 400
    assert "Choose a valid role." in resp.get_data(as_text=True)
    with client.session_transaction() as session:
        assert "pending_signup" not in session
    assert User.query.filter_by(username="sam.analyst").first() is None


def test_signup_rejects_the_retired_security_team_role(client, monkeypatch):
    assert _post_signup(client, monkeypatch, role="security_team").status_code == 400


def test_signup_accepts_each_user_role(client, monkeypatch):
    for role in ("cybersecurity_analyst", "threat_intel_analyst"):
        resp = _post_signup(client, monkeypatch, role=role)
        assert resp.status_code == 302, role
        with client.session_transaction() as session:
            assert session["pending_signup"]["role"] == role


def _assert_password_ui(html, confirm_label):
    assert html.count('class="btn-toggle-password"') == 2
    assert 'data-target="password"' in html and 'data-target="confirm_password"' in html
    assert 'data-confirm-of="password"' in html
    assert 'id="confirm_password_hint"' in html and 'role="status"' in html
    assert "js/password-toggle.js" in html and "js/password-match.js" in html
    assert confirm_label in html


def test_signup_page_has_eye_toggles_and_match_alert_on_both_password_fields(client):
    _assert_password_ui(client.get("/signup").get_data(as_text=True), "Confirm password")


def test_reset_password_page_has_the_same_password_controls(client):
    with client.session_transaction() as session:
        session["reset_verified"] = True
        session["reset_user_id"] = 1
    resp = client.get("/reset-password")
    assert resp.status_code == 200
    _assert_password_ui(resp.get_data(as_text=True), "Confirm new password")


# ------------------------------------------------------------------ usernames are free-form
def test_signup_accepts_a_short_username_or_one_with_spaces(client, monkeypatch):
    for name in ("ab", "Hazig Haikal", "nur@home"):
        resp = _post_signup(client, monkeypatch, username=name)
        assert resp.status_code == 302, name
        with client.session_transaction() as session:
            assert session["pending_signup"]["username"] == name


def test_signup_squeezes_repeated_spaces_in_the_username(client, monkeypatch):
    assert _post_signup(client, monkeypatch, username="  Hazig    Haikal ").status_code == 302
    with client.session_transaction() as session:
        assert session["pending_signup"]["username"] == "Hazig Haikal"


def test_signup_no_longer_mentions_the_old_length_rule(client, monkeypatch):
    html = _post_signup(client, monkeypatch, username="x" * 81).get_data(as_text=True)
    assert "at most 80 characters" in html and "3-30" not in html


def test_signup_refuses_only_empty_or_unsafe_usernames(client, monkeypatch):
    resp = _post_signup(client, monkeypatch, username="   ")
    assert resp.status_code == 400 and "Enter a username." in resp.get_data(as_text=True)
    resp = _post_signup(client, monkeypatch, username="two\nlines")
    assert resp.status_code == 400 and "line breaks or invisible characters" in resp.get_data(as_text=True)
    with client.session_transaction() as session:
        assert "pending_signup" not in session


def test_the_signup_form_allows_eighty_characters(client):
    html = client.get("/signup").get_data(as_text=True)
    assert 'id="username" name="username" value="" maxlength="80" required' in html


def test_a_user_with_a_spaced_name_can_sign_in_however_they_space_it(client, monkeypatch):
    from extensions import db

    user = User(username="Hazig Haikal", email="hazig@example.com", role="it_admin")
    user.set_password("StrongPass123!")
    db.session.add(user)
    db.session.commit()
    monkeypatch.setattr(auth_pages, "verify_captcha", lambda *args: True)

    for typed in ("Hazig Haikal", "  Hazig   Haikal  "):
        client.get("/logout")
        resp = client.post("/login", data={"username": typed, "password": "StrongPass123!", "captcha_answer": "0"})
        assert resp.status_code == 302 and "/dashboard" in resp.headers["Location"], typed
        client.post("/logout")
