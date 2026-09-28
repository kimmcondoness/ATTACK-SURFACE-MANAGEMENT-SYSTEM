import threading
import time
from datetime import datetime, timedelta

from extensions import db
from models import Asset, AuthorizedTarget, Scan
from scanner.base import ScanControl
from services import job_registry
from services.scan_progress_service import chain_progress
from tests.conftest import login

GRAPHQL_STATUS = (
    "query($id: Int!) { scanStatus(scanId: $id) "
    "{ scanId status paused targetDomain elapsedSeconds progressPercent phase } }"
)
GRAPHQL_ACTIVE = "query { activeScan { scanId status paused targetDomain elapsedSeconds progressPercent phase } }"


def _chain(owner, assets=2, lead_status="completed", started_ago=90):
    target = AuthorizedTarget(domain="example.com", owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    for i in range(assets):
        db.session.add(Asset(target_id=target.id, subdomain=f"h{i}.example.com"))
    started = datetime.utcnow() - timedelta(seconds=started_ago)
    lead = Scan(target_id=target.id, scan_type="asset_discovery", status=lead_status, started_by=owner.id, started_at=started)
    db.session.add(lead)
    db.session.commit()
    return target, lead


def _phase(target, owner, scan_type, status):
    scan = Scan(target_id=target.id, scan_type=scan_type, status=status, started_by=owner.id)
    db.session.add(scan)
    db.session.commit()
    return scan


# ------------------------------------------------------------------ progress maths
def test_progress_is_unknown_until_discovery_has_finished(app, analyst_user):
    _, lead = _chain(analyst_user, lead_status="running")

    progress = chain_progress(lead)

    assert progress["percent"] is None and progress["phase"] == "Discovering assets"


def test_progress_counts_finished_phases_out_of_three_per_asset_plus_discovery(app, analyst_user):
    target, lead = _chain(analyst_user, assets=2)  # 1 discovery + 2 assets x 3 phases = 7
    assert chain_progress(lead)["percent"] == 14  # discovery only: 1/7

    _phase(target, analyst_user, "port_discovery", "completed")
    _phase(target, analyst_user, "vulnerability_scan", "completed")
    running = _phase(target, analyst_user, "dork_scan", "running")

    progress = chain_progress(lead)
    assert progress["percent"] == 42  # 3/7 finished
    assert progress["phase"] == "Dork exposure check · asset 1 of 2"

    running.status = "completed"
    db.session.commit()
    assert chain_progress(lead)["percent"] == 57  # 4/7


def test_progress_never_goes_backwards_and_never_claims_100_early(app, analyst_user):
    target, lead = _chain(analyst_user, assets=2)
    seen = [chain_progress(lead)["percent"]]
    for scan_type in ("port_discovery", "vulnerability_scan", "dork_scan") * 2:
        _phase(target, analyst_user, scan_type, "completed")
        seen.append(chain_progress(lead)["percent"])

    assert seen == sorted(seen)
    assert max(seen) == 99


def test_progress_ignores_other_targets_and_earlier_scans(app, analyst_user):
    target, lead = _chain(analyst_user, assets=1)
    other, _ = _chain(analyst_user, assets=1)
    _phase(other, analyst_user, "port_discovery", "completed")
    baseline = chain_progress(lead)["percent"]

    _phase(other, analyst_user, "vulnerability_scan", "completed")

    assert chain_progress(lead)["percent"] == baseline


# ------------------------------------------------------------------ paused time
def test_paused_seconds_counts_only_time_spent_paused():
    control = ScanControl()
    assert control.paused_seconds() == 0

    control.request_pause()
    time.sleep(0.2)
    control.request_pause()  # a second pause request must not restart the clock
    control.request_resume()
    paused = control.paused_seconds()
    assert 0.15 <= paused < 0.6  # sleep() can return a little early on Windows

    time.sleep(0.2)
    assert abs(control.paused_seconds() - paused) < 0.01  # running time is not counted


def test_an_ongoing_pause_is_included():
    control = ScanControl()
    control.request_pause()
    time.sleep(0.15)
    assert control.paused_seconds() >= 0.1


# ------------------------------------------------------------------ GraphQL
def _gql(client, query, variables=None):
    return client.post("/graphql", json={"query": query, "variables": variables or {}}).get_json()["data"]


def test_scan_status_reports_elapsed_time_and_progress(client, analyst_user):
    target, lead = _chain(analyst_user, assets=1, started_ago=125)
    _phase(target, analyst_user, "port_discovery", "completed")
    login(client, "analyst", "AnalystPass123!")

    data = _gql(client, GRAPHQL_STATUS, {"id": lead.id})["scanStatus"]

    assert data["status"] == "completed" and data["targetDomain"] == "example.com"
    assert data["progressPercent"] == 100  # the chain thread is gone and the lead completed
    assert data["elapsedSeconds"] >= 0


def test_active_scan_is_empty_when_nothing_is_running(client, analyst_user):
    _chain(analyst_user)
    login(client, "analyst", "AnalystPass123!")

    assert _gql(client, GRAPHQL_ACTIVE)["activeScan"] is None


def test_active_scan_finds_the_running_chain_and_reports_pause_and_elapsed(client, analyst_user):
    target, lead = _chain(analyst_user, assets=1, lead_status="running", started_ago=65)
    control, release = ScanControl(), threading.Event()
    worker = threading.Thread(target=release.wait, daemon=True)
    worker.start()
    job_registry.register(lead.id, worker, control)
    try:
        login(client, "analyst", "AnalystPass123!")

        running = _gql(client, GRAPHQL_ACTIVE)["activeScan"]
        assert running["scanId"] == lead.id and running["status"] == "running"
        assert running["progressPercent"] is None and running["phase"] == "Discovering assets"
        assert 64 <= running["elapsedSeconds"] < 80

        control.request_pause()
        assert _gql(client, GRAPHQL_ACTIVE)["activeScan"]["status"] == "paused"
        assert _gql(client, GRAPHQL_STATUS, {"id": lead.id})["scanStatus"]["paused"] is True
    finally:
        release.set()
        worker.join(2)
        job_registry.unregister(lead.id)


def test_scan_status_is_not_visible_to_another_user(app, client, analyst_user):
    from models import User

    _, lead = _chain(analyst_user)
    other = User(username="other", email="other@example.com", role="cybersecurity_analyst")
    other.set_password("OtherPass123!")
    db.session.add(other)
    db.session.commit()
    login(client, "other", "OtherPass123!")

    assert _gql(client, GRAPHQL_STATUS, {"id": lead.id})["scanStatus"] is None
    assert _gql(client, GRAPHQL_ACTIVE)["activeScan"] is None


def test_dashboard_has_the_timer_and_progress_bar(client, analyst_user):
    login(client, "analyst", "AnalystPass123!")

    html = client.get("/dashboard/details").get_data(as_text=True)

    for element in ('id="scan-progress"', 'id="scan-timer"', 'role="progressbar"', 'id="scan-phase"', 'id="scan-percent"'):
        assert element in html, element


def test_long_dashboard_tables_are_paged_ten_rows_at_a_time(client, analyst_user):
    _chain(analyst_user)  # a target and a scan, so both tables are rendered
    login(client, "analyst", "AnalystPass123!")

    html = client.get("/dashboard/details").get_data(as_text=True)

    assert html.count('<table data-paginate="10">') == 2  # Your targets and Scan history
    assert "js/table-pager.js" in html
