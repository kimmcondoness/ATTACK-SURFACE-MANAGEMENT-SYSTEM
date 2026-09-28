from extensions import db
from models import Asset, AuthorizedTarget, Report, User, Vulnerability
from tests.conftest import login


def _analyst(username):
    user = User(username=username, email=f"{username}@example.com", role="cybersecurity_analyst")
    user.set_password("AnalystPass123!")
    db.session.add(user)
    db.session.commit()
    return user


def _target_with_findings(owner, domain, cves):
    target = AuthorizedTarget(domain=domain, owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain=f"www.{domain}")
    db.session.add(asset)
    db.session.commit()
    vulns = [Vulnerability(asset_id=asset.id, severity="medium", title=f"Finding {i}", cve=cve) for i, cve in enumerate(cves)]
    db.session.add_all(vulns)
    db.session.commit()
    return target, [v.id for v in vulns]


def _web_login(client, username):
    login(client, username, "AnalystPass123!")


def test_delete_removes_selected_findings(client, app):
    owner = _analyst("owner")
    _, (with_cve, without_cve) = _target_with_findings(owner, "example.com", ["CVE-2021-44228", None])

    _web_login(client, "owner")
    resp = client.post("/workspace/findings/delete", data={"vuln_ids": [without_cve]})
    assert resp.status_code == 302

    assert db.session.get(Vulnerability, without_cve) is None
    assert db.session.get(Vulnerability, with_cve) is not None


def test_delete_ignores_findings_on_other_users_targets(client, app):
    owner = _analyst("owner")
    intruder = _analyst("intruder")
    _, (theirs,) = _target_with_findings(owner, "example.com", [None])
    _target_with_findings(intruder, "mine.example", [None])

    _web_login(client, "intruder")
    client.post("/workspace/findings/delete", data={"vuln_ids": [theirs]})

    assert db.session.get(Vulnerability, theirs) is not None


def test_delete_without_selection_changes_nothing(client, app):
    owner = _analyst("owner")
    _, (only,) = _target_with_findings(owner, "example.com", [None])

    _web_login(client, "owner")
    client.post("/workspace/findings/delete", data={})

    assert db.session.get(Vulnerability, only) is not None


def test_report_shows_unread_until_downloaded(client, app, tmp_path):
    owner = _analyst("owner")
    target, _ = _target_with_findings(owner, "example.com", [None])
    report_file = tmp_path / "report.csv"
    report_file.write_text("a,b\n")
    report = Report(target_id=target.id, report_type="csv", file_path=str(report_file), generated_by=owner.id)
    db.session.add(report)
    db.session.commit()

    _web_login(client, "owner")
    assert "Unread" in client.get("/workspace/findings").get_data(as_text=True)

    assert client.get(f"/workspace/reports/{report.id}/download").status_code == 200

    page = client.get("/workspace/findings").get_data(as_text=True)
    assert "Unread" not in page
    assert ">Read<" in page
