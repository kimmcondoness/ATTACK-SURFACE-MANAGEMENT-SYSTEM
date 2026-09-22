from tests.conftest import login


def test_login_success(client, admin_user):
    resp = login(client, "admin", "AdminPass123!")
    assert resp.status_code == 200
    assert resp.get_json()["user"]["username"] == "admin"


def test_login_failure(client, admin_user):
    resp = login(client, "admin", "wrong-password")
    assert resp.status_code == 401


def test_me_requires_login(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_logout(client, admin_user):
    login(client, "admin", "AdminPass123!")
    resp = client.post("/api/auth/logout")
    assert resp.status_code == 200
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401
