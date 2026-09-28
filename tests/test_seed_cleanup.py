from database.seed import SAMPLE_FINDINGS, remove_sample_findings
from extensions import db
from models import Asset, AuthorizedTarget, Vulnerability


def _asset(owner):
    target = AuthorizedTarget(domain="example.com", owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain="www.example.com")
    db.session.add(asset)
    db.session.commit()
    return asset


def _add(asset, title, description, severity="medium"):
    db.session.add(Vulnerability(asset_id=asset.id, severity=severity, title=title, description=description))
    db.session.commit()


def test_only_the_old_made_up_findings_are_removed(app, analyst_user):
    asset = _asset(analyst_user)
    for title, wording in SAMPLE_FINDINGS:
        _add(asset, title, f"https://www.example.com {wording}")               # exactly what the old sample data wrote
    _add(asset, "Missing security headers", "An analyst wrote this one by hand.")   # same title, different wording: keep
    _add(asset, "[Config] Missing security header: Content-Security-Policy", "Real check.")
    _add(asset, "Possible CVE-2023-2512 affecting http nginx", "NVD lead.")

    assert remove_sample_findings() == 2

    assert sorted(v.title for v in Vulnerability.query.all()) == [
        "Missing security headers", "Possible CVE-2023-2512 affecting http nginx", "[Config] Missing security header: Content-Security-Policy"]


def test_nothing_happens_when_there_are_no_sample_findings(app, analyst_user):
    _add(_asset(analyst_user), "[Dork] Exposed environment file: /.env", "Real.", "critical")
    assert remove_sample_findings() == 0
    assert Vulnerability.query.count() == 1
