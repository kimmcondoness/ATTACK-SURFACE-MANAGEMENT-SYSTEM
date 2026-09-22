from tests.conftest import login


def test_create_target(client, analyst_user):
    login(client, "analyst", "AnalystPass123!")
    resp = client.post("/api/targets", json={"domain": "example.com", "authorized": True})
    assert resp.status_code == 201
    body = resp.get_json()["target"]
    assert body["domain"] == "example.com"
    assert body["authorized"] is True


def test_create_target_rejects_invalid_domain(client, analyst_user):
    login(client, "analyst", "AnalystPass123!")
    resp = client.post("/api/targets", json={"domain": "not a domain!!"})
    assert resp.status_code == 400


def test_security_team_cannot_create_target(client, app):
    from extensions import db
    from models import ROLE_SECURITY_TEAM, User

    user = User(username="sec", email="sec@example.com", role=ROLE_SECURITY_TEAM)
    user.set_password("SecPass123!")
    db.session.add(user)
    db.session.commit()

    login(client, "sec", "SecPass123!")
    resp = client.post("/api/targets", json={"domain": "example.com"})
    assert resp.status_code == 403
