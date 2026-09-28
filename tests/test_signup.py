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
