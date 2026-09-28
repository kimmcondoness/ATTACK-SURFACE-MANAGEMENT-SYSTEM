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


def test_threat_intel_cannot_create_target(client, app):
    from extensions import db
    from models import ROLE_THREAT_INTEL, User

    user = User(username="intel", email="intel@example.com", role=ROLE_THREAT_INTEL)
    user.set_password("IntelPass123!")
    db.session.add(user)
    db.session.commit()

    login(client, "intel", "IntelPass123!")
    resp = client.post("/api/targets", json={"domain": "example.com"})
    assert resp.status_code == 403


def test_threat_intel_cannot_update_finding_status(client, app):
    from extensions import db
    from models import ROLE_THREAT_INTEL, Asset, AuthorizedTarget, User, Vulnerability

    owner = User(username="owner", email="owner@example.com", role="cybersecurity_analyst")
    owner.set_password("OwnerPass123!")
    intel = User(username="intel", email="intel@example.com", role=ROLE_THREAT_INTEL)
    intel.set_password("IntelPass123!")
    db.session.add_all([owner, intel])
    db.session.commit()

    target = AuthorizedTarget(domain="example.com", owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain="www.example.com")
    db.session.add(asset)
    db.session.commit()
    vuln = Vulnerability(asset_id=asset.id, severity="high", title="Test finding")
    db.session.add(vuln)
    db.session.commit()

    login(client, "intel", "IntelPass123!")
    resp = client.put(f"/api/vulnerabilities/{vuln.id}/status", json={"status": "resolved"})
    assert resp.status_code == 403
    assert client.get("/api/vulnerabilities").status_code == 200
