import json
import re

from extensions import db
from models import Asset, AuthorizedTarget, PortService, User, Vulnerability
from services.radar_service import radar_snapshot
from tests.conftest import login


def _target(owner, domain, hosts):
    target = AuthorizedTarget(domain=domain, owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    assets = []
    for host in hosts:
        asset = Asset(target_id=target.id, subdomain=host)
        db.session.add(asset)
        assets.append(asset)
    db.session.commit()
    return target, assets


def _finding(asset, severity, title="A finding", status="open", **extra):
    vuln = Vulnerability(asset_id=asset.id, severity=severity, title=title, status=status, **extra)
    db.session.add(vuln)
    db.session.commit()
    return vuln


def test_assets_are_ranked_by_their_worst_live_finding(app, analyst_user):
    _, (clean, mid, worst) = _target(analyst_user, "example.com", ["a.example.com", "b.example.com", "c.example.com"])
    _finding(mid, "medium")
    _finding(worst, "low")
    _finding(worst, "critical")

    snap = radar_snapshot(analyst_user.id)

    assert [n["host"] for n in snap["assets"]] == ["c.example.com", "b.example.com", "a.example.com"]
    assert [n["severity"] for n in snap["assets"]] == ["critical", "medium", "none"]
    assert snap["assets"][0]["findings"] == 2


def test_resolved_and_false_positive_findings_do_not_count_as_live(app, analyst_user):
    _, (asset,) = _target(analyst_user, "example.com", ["a.example.com"])
    _finding(asset, "critical", status="resolved")
    _finding(asset, "high", status="false_positive")
    _finding(asset, "low", status="in_progress")

    snap = radar_snapshot(analyst_user.id)

    assert snap["assets"][0]["severity"] == "low"
    assert snap["stats"] == {"assets": 1, "critical_risks": 0, "active_alerts": 1}


def test_headline_numbers(app, analyst_user):
    _, (a, b) = _target(analyst_user, "example.com", ["a.example.com", "b.example.com"])
    _finding(a, "critical")
    _finding(a, "high")
    _finding(b, "medium")
    _finding(b, "low")

    assert radar_snapshot(analyst_user.id)["stats"] == {"assets": 2, "critical_risks": 2, "active_alerts": 4}


def test_open_port_counts_are_included(app, analyst_user):
    _, (asset,) = _target(analyst_user, "example.com", ["a.example.com"])
    db.session.add_all([PortService(asset_id=asset.id, port=80), PortService(asset_id=asset.id, port=443)])
    db.session.commit()

    assert radar_snapshot(analyst_user.id)["assets"][0]["ports"] == 2


def test_callouts_are_the_highest_priority_live_findings_with_short_titles(app, analyst_user):
    _, (a, b) = _target(analyst_user, "example.com", ["a.example.com", "b.example.com"])
    _finding(a, "low", title="Low one")
    _finding(a, "critical", title="[Dork] Exposed environment file: /.env and a very long tail that must be cut short")
    _finding(b, "high", title="High one")
    _finding(b, "medium", title="Medium one")
    _finding(b, "medium", title="Medium two", status="resolved")

    callouts = radar_snapshot(analyst_user.id)["callouts"]

    assert [c["severity"] for c in callouts] == ["critical", "high", "medium"]
    assert len(callouts[0]["title"]) <= 44 and callouts[0]["title"].endswith("…")


def test_target_filter_and_scope_label(app, analyst_user):
    first, (a,) = _target(analyst_user, "one.example.com", ["one.example.com"])
    second, (b,) = _target(analyst_user, "two.example.com", ["two.example.com"])
    _finding(b, "critical")

    everything = radar_snapshot(analyst_user.id)
    only_first = radar_snapshot(analyst_user.id, first.id)

    assert everything["scope"] == "All targets" and everything["stats"]["assets"] == 2
    assert only_first["scope"] == "one.example.com" and [n["host"] for n in only_first["assets"]] == ["one.example.com"]
    assert only_first["stats"]["critical_risks"] == 0


def test_someone_elses_target_is_never_included(app, analyst_user):
    stranger = User(username="stranger", email="s@example.com", role="cybersecurity_analyst")
    stranger.set_password("Stranger#123")
    db.session.add(stranger)
    db.session.commit()
    theirs, (asset,) = _target(stranger, "theirs.example.com", ["theirs.example.com"])
    _finding(asset, "critical")

    snap = radar_snapshot(analyst_user.id, theirs.id)  # asking for their target by id

    assert snap["assets"] == [] and snap["scope"] == "All targets"
    assert snap["stats"] == {"assets": 0, "critical_risks": 0, "active_alerts": 0}


def test_empty_radar_when_there_are_no_targets(app, analyst_user):
    snap = radar_snapshot(analyst_user.id)
    assert snap["assets"] == [] and snap["callouts"] == [] and snap["stats"]["assets"] == 0


def test_very_large_surfaces_are_capped_but_still_counted(app, analyst_user):
    _target(analyst_user, "example.com", [f"h{i}.example.com" for i in range(12)])

    snap = radar_snapshot(analyst_user.id, max_assets=5)

    assert len(snap["assets"]) == 5 and snap["stats"]["assets"] == 12


# ------------------------------------------------------------------ route
def test_radar_route_returns_json_for_the_analyst(client, analyst_user):
    _, (asset,) = _target(analyst_user, "example.com", ["a.example.com"])
    _finding(asset, "high", title="Something high")
    login(client, "analyst", "AnalystPass123!")

    resp = client.get("/workspace/radar")

    assert resp.status_code == 200 and resp.is_json
    body = resp.get_json()
    assert body["stats"]["critical_risks"] == 1 and body["assets"][0]["host"] == "a.example.com"


def test_radar_route_honours_target_id(client, analyst_user):
    first, _ = _target(analyst_user, "one.example.com", ["one.example.com"])
    _target(analyst_user, "two.example.com", ["two.example.com"])
    login(client, "analyst", "AnalystPass123!")

    body = client.get(f"/workspace/radar?target_id={first.id}").get_json()

    assert body["scope"] == "one.example.com" and body["stats"]["assets"] == 1


def test_radar_route_is_for_analysts_only(app, client, admin_user):
    anonymous = client.get("/workspace/radar")
    assert anonymous.status_code == 302 and "login" in anonymous.headers["Location"]

    login(client, "admin", "AdminPass123!")
    assert client.get("/workspace/radar").status_code == 403


# ------------------------------------------------------------------ page
def test_dashboard_embeds_the_radar_with_its_first_snapshot(client, analyst_user):
    _, (asset,) = _target(analyst_user, "example.com", ["a.example.com"])
    _finding(asset, "critical")
    login(client, "analyst", "AnalystPass123!")

    html = client.get("/dashboard/details").get_data(as_text=True)

    for element in ('id="radar-widget"', 'id="radar-canvas"', 'id="radar-pause"', "Assets Found", "Critical Risks", "Active Alerts", "js/radar.js"):
        assert element in html, element
    assert html.index('id="radar-widget"') < html.index('id="chart-range-picker"')  # sits above the charts

    embedded = re.search(r'<script id="radar-initial-data" type="application/json">(.*?)</script>', html, re.S)
    snapshot = json.loads(embedded.group(1))
    assert snapshot["stats"] == {"assets": 1, "critical_risks": 1, "active_alerts": 1}


def test_radar_data_in_the_page_cannot_break_out_of_its_script_tag(client, analyst_user):
    _, (asset,) = _target(analyst_user, "example.com", ["</script><b>x.example.com"])
    _finding(asset, "high", title="</script><script>alert(1)</script>")
    login(client, "analyst", "AnalystPass123!")

    html = client.get("/dashboard/details").get_data(as_text=True)

    assert "<script>alert(1)</script>" not in html
    embedded = re.search(r'<script id="radar-initial-data" type="application/json">(.*?)</script>', html, re.S)
    assert json.loads(embedded.group(1))["callouts"][0]["title"].startswith("</script>")


def test_radar_starts_idle_until_a_scan_begins(client, analyst_user):
    login(client, "analyst", "AnalystPass123!")

    html = client.get("/dashboard/details").get_data(as_text=True)

    assert 'id="radar-live-text">Radar idle<' in html
    assert re.search(r'<button[^>]*id="radar-pause"[^>]* disabled>', html)
    assert "scan:state" in open("static/js/live-scan.js", encoding="utf-8").read()  # the scan panel is what wakes it
