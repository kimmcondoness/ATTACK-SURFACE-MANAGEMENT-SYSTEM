import re
import time

import pytest

from extensions import db
from models import ROLE_THREAT_INTEL, Asset, AuditLog, AuthorizedTarget, User, Vulnerability
from tests.conftest import login
from utils.device_trust import issue_device_trust_token, verify_device_trust_token

TABS = ("profile", "access", "targets", "authentication", "activity")


@pytest.fixture
def admin_client(client, admin_user):
    login(client, "admin", "AdminPass123!")
    return client


def _user(username, role="cybersecurity_analyst", password="UserPass123!", **fields):
    user = User(username=username, email=f"{username}@example.com", role=role, **fields)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def _actions():
    return [(e.action, e.detail) for e in AuditLog.query.order_by(AuditLog.id).all()]


# ------------------------------------------------------------------ access control
def test_only_the_it_admin_can_open_the_user_pages(app, client, analyst_user):
    login(client, "analyst", "AnalystPass123!")

    for tab in TABS:
        resp = client.get(f"/admin/users/{analyst_user.id}/{tab}")
        assert resp.status_code == 302 and "/admin/users" not in resp.headers["Location"], tab


def test_non_admins_cannot_change_a_user_even_by_posting_directly(app, client, analyst_user):
    victim = _user("victim")
    login(client, "analyst", "AnalystPass123!")

    posts = {
        f"/admin/users/{victim.id}/profile": {"first_name": "Evil", "last_name": "X", "username": "hacked", "email": "hacked@example.com"},
        f"/admin/users/{victim.id}/access": {"role": "it_admin"},
        f"/admin/users/{victim.id}/authentication/password": {"password": "Hacked#Pass1", "confirm_password": "Hacked#Pass1"},
        f"/admin/users/{victim.id}/authentication/lock": {},
        f"/admin/users/{victim.id}/authentication/revoke": {},
    }
    for path, data in posts.items():
        assert client.post(path, data=data).status_code == 302, path

    fresh = db.session.get(User, victim.id)
    db.session.refresh(fresh)
    assert (fresh.username, fresh.email, fresh.role, fresh.is_active_flag) == ("victim", "victim@example.com", "cybersecurity_analyst", True)
    assert fresh.check_password("UserPass123!")


def test_anonymous_visitors_are_sent_to_the_login_page(client, analyst_user):
    resp = client.get(f"/admin/users/{analyst_user.id}/profile")
    assert resp.status_code == 302 and "login" in resp.headers["Location"]


def test_threat_intel_users_are_also_refused(app, client):
    _user("intel", role=ROLE_THREAT_INTEL)
    login(client, "intel", "UserPass123!")
    assert client.get("/admin/users/1/profile").status_code == 302


# ------------------------------------------------------------------ viewing
def test_every_tab_renders_with_the_manage_menu(admin_client, analyst_user):
    for tab in TABS:
        resp = admin_client.get(f"/admin/users/{analyst_user.id}/{tab}")
        html = resp.get_data(as_text=True)
        assert resp.status_code == 200, tab
        assert "analyst@example.com" in html
        assert all(label in html for label in ("Profile", "Access", "Targets", "Authentication", "Activity")), tab


def test_user_home_redirects_to_profile_and_unknown_things_404(admin_client, analyst_user):
    assert admin_client.get(f"/admin/users/{analyst_user.id}").headers["Location"].endswith(f"/admin/users/{analyst_user.id}/profile")
    assert admin_client.get("/admin/users/9999/profile").status_code == 404
    assert admin_client.get(f"/admin/users/{analyst_user.id}/mailbox").status_code == 404


def test_targets_tab_lists_the_users_targets_with_counts(admin_client, analyst_user):
    target = AuthorizedTarget(domain="example.com", owner_id=analyst_user.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain="www.example.com")
    db.session.add(asset)
    db.session.commit()
    db.session.add(Vulnerability(asset_id=asset.id, severity="high", title="Open finding"))
    db.session.add(Vulnerability(asset_id=asset.id, severity="low", title="Done", status="resolved"))
    db.session.commit()

    html = admin_client.get(f"/admin/users/{analyst_user.id}/targets").get_data(as_text=True)

    assert "example.com" in html and "Authorized" in html
    assert "<td>1</td>\n          <td>1</td>" in html  # 1 asset, 1 live finding (resolved one excluded)


# ------------------------------------------------------------------ identity
def test_admin_can_change_name_username_and_email(admin_client, analyst_user):
    resp = admin_client.post(
        f"/admin/users/{analyst_user.id}/profile",
        data={"first_name": "Aisha", "last_name": "Rahman", "username": "aisha.r", "email": "Aisha.R@Example.com"},
    )

    assert resp.status_code == 302
    user = db.session.get(User, analyst_user.id)
    assert (user.first_name, user.last_name, user.username, user.email) == ("Aisha", "Rahman", "aisha.r", "aisha.r@example.com")
    assert ("user_identity_updated", f"target_user_id={user.id} changed=first_name,last_name,username,email") in _actions()


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"username": "   "}, "Enter a username"),
        ({"username": "x" * 81}, "at most 80 characters"),
        ({"username": "two\nlines"}, "line breaks or invisible characters"),
        ({"email": "not-an-email"}, "valid email"),
        ({"first_name": ""}, "First and last name are required"),
        ({"username": "admin"}, "already taken"),
        ({"email": "admin@example.com"}, "already exists"),
    ],
)
def test_bad_identity_changes_are_refused_and_the_form_keeps_what_was_typed(admin_client, analyst_user, overrides, message):
    data = {"first_name": "Aisha", "last_name": "Rahman", "username": "aisha.r", "email": "aisha@example.com", **overrides}

    resp = admin_client.post(f"/admin/users/{analyst_user.id}/profile", data=data)

    assert resp.status_code == 400
    html = resp.get_data(as_text=True)
    assert message in html and "<details class=\"ud-edit\" open>" in html
    user = db.session.get(User, analyst_user.id)
    db.session.refresh(user)
    assert user.username == "analyst"


def test_saving_without_changes_reports_nothing_to_change(admin_client, analyst_user):
    resp = admin_client.post(
        f"/admin/users/{analyst_user.id}/profile",
        data={"first_name": "A", "last_name": "B", "username": "analyst", "email": "analyst@example.com"},
    )
    assert resp.status_code == 302
    admin_client.post(
        f"/admin/users/{analyst_user.id}/profile",
        data={"first_name": "A", "last_name": "B", "username": "analyst", "email": "analyst@example.com"},
    )
    assert "Nothing to change." in admin_client.get(f"/admin/users/{analyst_user.id}/profile").get_data(as_text=True)


# ------------------------------------------------------------------ role
def test_admin_can_change_another_users_role(admin_client, analyst_user):
    admin_client.post(f"/admin/users/{analyst_user.id}/access", data={"role": "threat_intel_analyst"})

    assert db.session.get(User, analyst_user.id).role == "threat_intel_analyst"
    assert ("user_role_updated", f"target_user_id={analyst_user.id} role=cybersecurity_analyst->threat_intel_analyst") in _actions()


def test_admin_cannot_change_their_own_role_or_pick_a_bad_one(admin_client, admin_user, analyst_user):
    admin_client.post(f"/admin/users/{admin_user.id}/access", data={"role": "cybersecurity_analyst"})
    admin_client.post(f"/admin/users/{analyst_user.id}/access", data={"role": "root"})

    assert db.session.get(User, admin_user.id).role == "it_admin"
    assert db.session.get(User, analyst_user.id).role == "cybersecurity_analyst"


# ------------------------------------------------------------------ password
def test_admin_can_reset_a_password_and_it_is_never_logged(admin_client, analyst_user):
    resp = admin_client.post(
        f"/admin/users/{analyst_user.id}/authentication/password",
        data={"password": "Fresh#Pass99", "confirm_password": "Fresh#Pass99"},
    )

    assert resp.status_code == 302
    assert db.session.get(User, analyst_user.id).check_password("Fresh#Pass99")
    assert "password_reset_by_admin" in [a for a, _ in _actions()]
    assert all("Fresh#Pass99" not in (detail or "") for _, detail in _actions())


@pytest.mark.parametrize(
    "password,confirm,message",
    [("weakpass", "weakpass", "Password must have"), ("Fresh#Pass99", "Fresh#Pass98", "do not match")],
)
def test_weak_or_mismatched_password_resets_are_refused(admin_client, analyst_user, password, confirm, message):
    admin_client.post(
        f"/admin/users/{analyst_user.id}/authentication/password",
        data={"password": password, "confirm_password": confirm},
    )

    user = db.session.get(User, analyst_user.id)
    db.session.refresh(user)
    assert user.check_password("AnalystPass123!")
    assert message in admin_client.get(f"/admin/users/{analyst_user.id}/authentication").get_data(as_text=True)


# ------------------------------------------------------------------ lock / MFA
def test_locking_signs_the_user_out_at_once_and_unlocking_restores_access(app, admin_client, analyst_user):
    user_client = app.test_client()
    login(user_client, "analyst", "AnalystPass123!")
    assert user_client.get("/api/targets").status_code == 200

    admin_client.post(f"/admin/users/{analyst_user.id}/authentication/lock")
    assert db.session.get(User, analyst_user.id).is_active_flag is False
    assert user_client.get("/api/targets").status_code == 401

    admin_client.post(f"/admin/users/{analyst_user.id}/authentication/lock")
    assert db.session.get(User, analyst_user.id).is_active_flag is True
    assert user_client.get("/api/targets").status_code == 200


def test_admin_cannot_lock_their_own_account(admin_client, admin_user):
    admin_client.post(f"/admin/users/{admin_user.id}/authentication/lock")
    assert db.session.get(User, admin_user.id).is_active_flag is True


def test_reset_mfa_makes_earlier_trusted_devices_verify_again(app, admin_client, analyst_user):
    old_token = issue_device_trust_token(analyst_user.id)
    assert verify_device_trust_token(old_token, analyst_user.id) is True

    time.sleep(1.1)  # tokens are timestamped in whole seconds
    admin_client.post(f"/admin/users/{analyst_user.id}/authentication/revoke")

    assert verify_device_trust_token(old_token, analyst_user.id) is False
    time.sleep(1.1)
    assert verify_device_trust_token(issue_device_trust_token(analyst_user.id), analyst_user.id) is True
    assert ("mfa_reset", f"target_user_id={analyst_user.id}") in _actions()


def test_an_admin_password_reset_also_revokes_trusted_devices(app, admin_client, analyst_user):
    token = issue_device_trust_token(analyst_user.id)
    time.sleep(1.1)
    admin_client.post(
        f"/admin/users/{analyst_user.id}/authentication/password",
        data={"password": "Fresh#Pass99", "confirm_password": "Fresh#Pass99"},
    )
    assert verify_device_trust_token(token, analyst_user.id) is False


def test_revoking_one_user_does_not_affect_anothers_trusted_device(app, admin_client, analyst_user):
    other = _user("other")
    token = issue_device_trust_token(other.id)
    time.sleep(1.1)
    admin_client.post(f"/admin/users/{analyst_user.id}/authentication/revoke")
    assert verify_device_trust_token(token, other.id) is True


# ------------------------------------------------------------------ activity + dashboard
def test_activity_tab_shows_admin_changes_made_to_the_account(admin_client, analyst_user):
    admin_client.post(f"/admin/users/{analyst_user.id}/access", data={"role": "threat_intel_analyst"})

    html = admin_client.get(f"/admin/users/{analyst_user.id}/activity").get_data(as_text=True)

    assert "User role updated" in html and "cybersecurity_analyst-&gt;threat_intel_analyst" in html
    assert "admin" in html


def test_admin_dashboard_links_to_the_directory_and_shows_new_summaries(admin_client, analyst_user):
    analyst = db.session.get(User, analyst_user.id)
    analyst.is_active_flag = False
    db.session.commit()

    html = admin_client.get("/admin/dashboard").get_data(as_text=True)

    assert f"/admin/users/{analyst_user.id}" in html and ">Manage<" in html
    assert "Deactivated" in html and "Recent activity" in html
    assert 'id="table-search"' in html and "data-filterable" in html


def test_a_user_with_no_first_or_last_name_shows_their_username_not_none_none(admin_client, admin_user):
    # database/seed.py's default admin, and any account created via the /api/users API, never
    # set first_name/last_name -- Jinja renders a bare None as the literal text "None".
    nameless = _user("nameless", first_name=None, last_name=None)

    html = admin_client.get("/admin/dashboard").get_data(as_text=True)

    cell = re.search(r'<td><a href="[^"]+">([^<]*)</a><br><span class="text-mono">nameless</span></td>', html)
    assert cell is not None
    assert "None" not in cell.group(1)
    assert cell.group(1) == "nameless"  # falls back to the username
