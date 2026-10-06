import threading
from datetime import datetime, timedelta

import pytest

from extensions import db
from models import ROLE_ANALYST, ROLE_THREAT_INTEL, AuditLog, AuthorizedTarget, MonitorHeartbeat, Scan, User
from scanner.base import ScanControl
from services import job_registry, monitor_service
from tests.conftest import login

PASSWORD = "SharePass#123"


def _user(username, role=ROLE_ANALYST, first="", last=""):
    user = User(username=username, email=f"{username}@example.com", role=role, first_name=first or None, last_name=last or None)
    user.set_password(PASSWORD)
    db.session.add(user)
    db.session.commit()
    return user


def _target(owner, domain, interval=None, **fields):
    target = AuthorizedTarget(domain=domain, owner_id=owner.id, authorized=fields.pop("authorized", True), monitor_interval_days=interval, **fields)
    db.session.add(target)
    db.session.commit()
    return target


def _beat():
    db.session.add(MonitorHeartbeat(id=1, started_at=datetime.utcnow() - timedelta(hours=1), last_tick_at=datetime.utcnow()))
    db.session.commit()


def _sign_in(client, username, password=PASSWORD):
    client.post("/api/auth/logout")
    assert login(client, username, password).status_code == 200


@pytest.fixture
def ana(analyst_user):
    analyst_user.first_name, analyst_user.last_name = "Ana", "Analyst"
    db.session.commit()
    return analyst_user


@pytest.fixture
def ben(app):
    return _user("ben", first="Ben", last="Other")


# ============================================================ who set monitoring up
def test_turning_monitoring_on_records_who_and_when(app, ana):
    target = _target(ana, "a.example.com")
    assert target.monitor_set_by is None

    monitor_service.set_interval(target, "weekly", ana.id)

    assert target.monitor_set_by == ana.id and abs((datetime.utcnow() - target.monitor_set_at).total_seconds()) < 5


def test_saving_the_same_schedule_again_does_not_take_over_the_attribution(app, ana, admin_user):
    target = _target(ana, "a.example.com")
    monitor_service.set_interval(target, "weekly", ana.id)
    first_time = target.monitor_set_at

    monitor_service.set_interval(target, "weekly", admin_user.id)                                    # an admin pressing Save, nothing changed

    assert target.monitor_set_by == ana.id and target.monitor_set_at == first_time


def test_changing_the_schedule_passes_the_attribution_to_whoever_changed_it(app, ana, admin_user):
    target = _target(ana, "a.example.com")
    monitor_service.set_interval(target, "weekly", ana.id)

    monitor_service.set_interval(target, "daily", admin_user.id)

    assert target.monitor_set_by == admin_user.id


def test_turning_monitoring_off_clears_it(app, ana):
    target = _target(ana, "a.example.com")
    monitor_service.set_interval(target, "daily", ana.id)
    monitor_service.set_interval(target, "off", ana.id)
    assert target.monitor_set_by is None and target.monitor_set_at is None


# ============================================================ who sees what
def test_an_analyst_sees_only_their_own_monitored_targets(app, ana, ben):
    mine = _target(ana, "mine.example.com", 7, monitor_set_by=ana.id, monitor_set_at=datetime(2026, 10, 1))
    _target(ana, "off.example.com")
    _target(ana, "unauthorized.example.com", 1, authorized=False)
    _target(ben, "theirs.example.com", 1, monitor_set_by=ben.id)

    entries = monitor_service.monitored_entries(ana)

    assert [e["target"].id for e in entries] == [mine.id]
    [entry] = entries
    assert (entry["set_by_name"], entry["set_by_you"], entry["owner_name"], entry["interval_label"]) == ("Ana Analyst", True, "Ana Analyst", "Weekly")
    assert entry["set_at"] == datetime(2026, 10, 1) and entry["state"] == "due"                         # never scanned yet


def test_admins_and_threat_intel_see_everyones_with_who_set_each_up(app, ana, ben, admin_user):
    intel = _user("intel", ROLE_THREAT_INTEL, "Ines", "Intel")
    _target(ana, "b.example.com", 7, monitor_set_by=ana.id)
    _target(ben, "a.example.com", 1, monitor_set_by=admin_user.id)                                   # an admin set Ben's up for him

    for viewer in (admin_user, intel):
        entries = monitor_service.monitored_entries(viewer)
        assert [(e["target"].domain, e["set_by_name"]) for e in entries] == [("a.example.com", "admin"), ("b.example.com", "Ana Analyst")]
        assert [e["set_by_you"] for e in entries] == [viewer.id == admin_user.id, False]
    assert monitor_service.monitored_entries(admin_user)[0]["set_by_role"] == "it_admin"
    assert monitor_service.monitored_entries(admin_user)[0]["owner_name"] == "Ben Other"


def test_a_scan_in_progress_is_shown_as_scanning(app, ana):
    target = _target(ana, "a.example.com", 1, monitor_last_run_at=datetime.utcnow(), monitor_set_by=ana.id)
    lead = Scan(target_id=target.id, scan_type="asset_discovery", status="running", started_by=ana.id)
    db.session.add(lead)
    db.session.commit()
    release = threading.Event()
    thread = threading.Thread(target=release.wait, daemon=True)
    thread.start()
    job_registry.register(lead.id, thread, ScanControl())
    try:
        assert monitor_service.monitored_entries(ana)[0]["state"] == "scanning"
    finally:
        release.set()
        job_registry.unregister(lead.id)


def test_a_scheduled_target_is_not_due_yet(app, ana):
    _target(ana, "a.example.com", 7, monitor_last_run_at=datetime.utcnow() - timedelta(days=1), monitor_set_by=ana.id)
    assert monitor_service.monitored_entries(ana)[0]["state"] == "scheduled"


# ---- monitoring turned on before the setter was recorded
def _audit(user, target, interval, minutes_ago=0):
    db.session.add(AuditLog(user_id=user.id, action="monitoring_updated", detail=f"target_id={target.id} interval={interval}",
                            timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago)))
    db.session.commit()


def test_older_monitoring_is_attributed_from_the_audit_log(app, ana, admin_user):
    target = _target(ana, "old.example.com", 7)                                                      # no monitor_set_by: set up before it was recorded
    _audit(ana, target, "daily", 90)
    _audit(admin_user, target, "weekly", 30)

    [entry] = monitor_service.monitored_entries(ana)

    assert entry["set_by_name"] == "admin" and entry["set_by_you"] is False and entry["set_at"] is not None


def test_older_monitoring_with_no_audit_trail_is_the_owners(app, ana):
    _target(ana, "old.example.com", 7)
    [entry] = monitor_service.monitored_entries(ana)
    assert entry["set_by_name"] == "Ana Analyst" and entry["set_by_you"] is True and entry["set_at"] is None


def test_the_audit_log_forgets_a_setter_once_monitoring_was_switched_off(app, ana, admin_user):
    target = _target(ana, "old.example.com", 7)
    _audit(admin_user, target, "daily", 60)
    _audit(ana, target, "off", 30)                                                                   # off, then on again with nobody recorded

    assert monitor_service.monitored_entries(ana)[0]["set_by_name"] == "Ana Analyst"


def test_a_setter_who_has_since_been_deleted_is_named_as_such(app, ana):
    _target(ana, "a.example.com", 7, monitor_set_by=424242)
    entry = monitor_service.monitored_entries(ana)[0]
    assert entry["set_by_name"] == "a former user" and entry["set_by_role"] is None


# ============================================================ the engine is only "active" while something is monitored
def test_the_engine_is_idle_when_nobody_has_monitoring_on(app, ana):
    _beat()
    _target(ana, "off.example.com")

    status = monitor_service.engine_status(app, target_ids=[1])

    assert status["state"] == "idle" and status["label"] == "Monitoring engine idle"
    assert (status["monitored_targets"], status["your_monitored_targets"], status["other_monitored_targets"]) == (0, 0, 0)


def test_the_engine_is_active_when_any_user_has_monitoring_on(app, ana, ben):
    _beat()
    mine = _target(ana, "mine.example.com")
    _target(ben, "theirs.example.com", 7)

    status = monitor_service.engine_status(app, target_ids=[mine.id])

    assert status["state"] == "active"                                                               # someone else's monitoring is enough
    assert (status["monitored_targets"], status["your_monitored_targets"], status["other_monitored_targets"]) == (1, 0, 1)


def test_the_counts_split_yours_from_other_users(app, ana, ben):
    _beat()
    a = _target(ana, "a.example.com", 7)
    b = _target(ana, "b.example.com", 1)
    _target(ben, "c.example.com", 30)

    status = monitor_service.engine_status(app, target_ids=[a.id, b.id])

    assert (status["monitored_targets"], status["your_monitored_targets"], status["other_monitored_targets"]) == (3, 2, 1)
    everyone = monitor_service.engine_status(app)                                                    # no viewer scope: nothing is "other"
    assert (everyone["your_monitored_targets"], everyone["other_monitored_targets"]) == (3, 0)
    assert monitor_service.engine_status(app, target_ids=[])["your_monitored_targets"] == 0


def test_a_silent_engine_is_still_reported_as_stalled_even_with_nothing_to_monitor(app, monkeypatch):
    monkeypatch.setitem(app.config, "MONITOR_SCHEDULER_ENABLED", True)
    db.session.add(MonitorHeartbeat(id=1, started_at=datetime.utcnow(), last_tick_at=datetime.utcnow() - timedelta(hours=1)))
    db.session.commit()
    assert monitor_service.engine_status(app)["state"] == "stalled"


def test_the_public_health_check_treats_idle_as_healthy(client):
    _beat()
    resp = client.get("/api/health/monitoring")
    assert resp.status_code == 200 and resp.get_json()["monitoring"]["state"] == "idle"


def test_the_dashboard_says_idle_when_nothing_is_monitored(client, ana):
    _beat()
    _target(ana, "off.example.com")
    _sign_in(client, "analyst", "AnalystPass123!")

    html = " ".join(client.get("/dashboard/details").get_data(as_text=True).split())

    assert "monitor-engine-idle" in html and "Monitoring engine idle" in html and "no monitoring is turned on" in html
    assert "monitor-engine-active" not in html


def test_the_dashboard_counts_other_users_monitoring_but_shows_none_of_it(client, ana, ben):
    _beat()
    _target(ana, "mine.example.com")
    _target(ben, "secret-target.example.com", 7, monitor_set_by=ben.id)
    _sign_in(client, "analyst", "AnalystPass123!")

    html = " ".join(client.get("/dashboard/details").get_data(as_text=True).split())

    assert "monitor-engine-active" in html and "1 target monitored: 0 yours, 1 by other users" in html
    assert "0 targets monitored" in html                                                             # the panel is still about your own
    assert "secret-target.example.com" not in html and "Ben Other" not in html


def test_the_status_endpoint_carries_the_split(client, ana, ben):
    _beat()
    _target(ana, "a.example.com", 7)
    _target(ben, "b.example.com", 7)
    _sign_in(client, "analyst", "AnalystPass123!")
    engine = client.get("/workspace/monitoring/status").get_json()["engine"]
    assert (engine["state"], engine["monitored_targets"], engine["your_monitored_targets"], engine["other_monitored_targets"]) == ("active", 2, 1, 1)


# ============================================================ the sidebar section under Network
def _sidebar(html):
    return html.split('<aside class="ws-sidebar">')[1].split("</aside>")[0]


def test_the_sidebar_has_a_monitoring_section_directly_under_network(client, ana, ben):
    _target(ana, "mine.example.com", 7, monitor_set_by=ana.id)
    _target(ben, "theirs.example.com", 7, monitor_set_by=ben.id)
    _sign_in(client, "analyst", "AnalystPass123!")

    side = " ".join(_sidebar(client.get("/dashboard/details").get_data(as_text=True)).split())

    assert side.index("Network") < side.index("Monitoring <span") < side.index("Findings &amp; CVE Report")
    assert "mine.example.com" in side and "Weekly &middot; set up by Ana Analyst (you)" in side
    assert "theirs.example.com" not in side and "Ben Other" not in side                              # one analyst never sees another's
    assert side.split("Monitoring <span")[1].startswith(' class="count">1</span>')


def test_the_section_is_on_every_analyst_page(client, ana):
    _target(ana, "mine.example.com", 7, monitor_set_by=ana.id)
    _sign_in(client, "analyst", "AnalystPass123!")
    for path in ("/dashboard", "/dashboard/details", "/workspace/findings", "/workspace/monitoring"):
        assert "mine.example.com" in _sidebar(client.get(path).get_data(as_text=True)), path


def test_the_section_says_so_when_nothing_is_monitored(client, ana):
    _target(ana, "off.example.com")
    _sign_in(client, "analyst", "AnalystPass123!")
    side = _sidebar(client.get("/dashboard").get_data(as_text=True))
    assert "No target monitored yet" in side and "Monitoring overview" in side


def test_the_section_names_an_admin_who_set_up_the_analysts_monitoring(client, ana, admin_user):
    target = _target(ana, "mine.example.com")
    monitor_service.set_interval(target, "daily", admin_user.id)
    _sign_in(client, "analyst", "AnalystPass123!")
    side = " ".join(_sidebar(client.get("/dashboard").get_data(as_text=True)).split())
    assert "Daily" in side and "set up by admin" in side and "(you)" not in side


def test_threat_intel_and_admin_get_a_monitoring_link_with_the_organisation_count(client, ana, ben, admin_user):
    _user("intel", ROLE_THREAT_INTEL)
    _target(ana, "a.example.com", 7)
    _target(ben, "b.example.com", 7)
    _sign_in(client, "intel")
    side = " ".join(_sidebar(client.get("/workspace/threat-intel").get_data(as_text=True)).split())
    assert 'href="/workspace/monitoring"' in side and 'Monitoring <span class="count">2</span>' in side

    _sign_in(client, "admin", "AdminPass123!")
    side = " ".join(_sidebar(client.get("/admin/dashboard").get_data(as_text=True)).split())
    assert 'href="/workspace/monitoring"' in side and 'Monitoring <span class="count">2</span>' in side


# ============================================================ the overview page
def test_the_overview_needs_a_sign_in(client):
    resp = client.get("/workspace/monitoring")
    assert resp.status_code == 302 and "login" in resp.headers["Location"]


def test_an_analysts_overview_lists_their_targets_and_who_set_each_up(client, ana, ben):
    mine = _target(ana, "mine.example.com", 7, monitor_set_by=ana.id, monitor_set_at=datetime(2026, 10, 1, 9, 30))
    _target(ben, "theirs.example.com", 7, monitor_set_by=ben.id)
    _sign_in(client, "analyst", "AnalystPass123!")

    html = " ".join(client.get("/workspace/monitoring").get_data(as_text=True).split())

    assert f'id="target-{mine.id}"' in html and "mine.example.com" in html and "1 target monitored" in html
    assert "<strong>Ana Analyst</strong> <span class=\"pill pill-active\">You</span>" in html and "Analyst</span>" in html
    assert "2026-10-01 09:30" in html and "Due now" in html
    assert "<th>Owner</th>" not in html                                                              # an analyst's own targets: the owner is always them
    assert "theirs.example.com" not in html and "Ben Other" not in html


def test_the_admin_overview_shows_every_target_with_its_owner_and_who_set_it_up(client, ana, ben, admin_user):
    _target(ana, "a.example.com", 7, monitor_set_by=ana.id)
    _target(ben, "b.example.com", 1, monitor_set_by=admin_user.id)
    _sign_in(client, "admin", "AdminPass123!")

    html = " ".join(client.get("/workspace/monitoring").get_data(as_text=True).split())

    assert "<th>Owner</th>" in html and "2 targets monitored" in html
    assert "a.example.com" in html and "b.example.com" in html and "Ben Other" in html
    assert ">IT Admin</span>" in html and "Every target in the organisation" in html
    assert "Your targets</a> on the Dashboard" not in html                                           # admins do not change schedules here


def test_the_overview_for_threat_intel_is_read_only_and_organisation_wide(client, ana, ben):
    _user("intel", ROLE_THREAT_INTEL)
    _target(ana, "a.example.com", 7)
    _target(ben, "b.example.com", 7)
    _sign_in(client, "intel")
    resp = client.get("/workspace/monitoring")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "a.example.com" in html and "b.example.com" in html
    assert 'action="/workspace/monitoring/' not in html                                              # nothing here changes a schedule


def test_an_empty_overview_explains_how_to_start(client, ana):
    _target(ana, "off.example.com")
    _sign_in(client, "analyst", "AnalystPass123!")
    html = client.get("/workspace/monitoring").get_data(as_text=True)
    assert "None of your targets has continuous monitoring turned on yet." in html and "Daily, Weekly or Monthly" in html


def test_the_overview_shows_the_engine_status_too(client, ana):
    _beat()
    _target(ana, "a.example.com", 7)
    _sign_in(client, "analyst", "AnalystPass123!")
    html = " ".join(client.get("/workspace/monitoring").get_data(as_text=True).split())
    assert "monitor-engine-active" in html and "1 target monitored" in html and "js/monitor-status.js" in html


# ============================================================ end to end: who made it, through the real form
def test_monitoring_turned_on_through_the_dashboard_is_attributed_everywhere(client, ana, admin_user):
    target = _target(ana, "live.example.com")
    _sign_in(client, "analyst", "AnalystPass123!")
    client.post(f"/workspace/monitoring/{target.id}", data={"interval": "weekly"})

    mine = " ".join(client.get("/workspace/monitoring").get_data(as_text=True).split())
    assert "<strong>Ana Analyst</strong>" in mine and ">You</span>" in mine

    _sign_in(client, "admin", "AdminPass123!")                                                       # the admin moves it to daily
    client.post(f"/workspace/monitoring/{target.id}", data={"interval": "daily"})
    overview = " ".join(client.get("/workspace/monitoring").get_data(as_text=True).split())
    assert "<strong>admin</strong>" in overview and "Ana Analyst" in overview and "Daily" in overview

    _sign_in(client, "analyst", "AnalystPass123!")
    side = " ".join(_sidebar(client.get("/dashboard").get_data(as_text=True)).split())
    assert "Daily" in side and "set up by admin" in side

    client.post(f"/workspace/monitoring/{target.id}", data={"interval": "off"})
    assert "No target monitored yet" in _sidebar(client.get("/dashboard").get_data(as_text=True))


def test_the_section_is_open_when_something_is_monitored_and_capped_at_eight(client, ana):
    _sign_in(client, "analyst", "AnalystPass123!")
    side = " ".join(_sidebar(client.get("/dashboard").get_data(as_text=True)).split())
    assert "open" not in side.split("<summary>Monitoring")[0].split("<details")[-1]                   # nothing monitored: collapsed

    for i in range(10):
        _target(ana, f"t{i:02d}.example.com", 7, monitor_set_by=ana.id)
    side = " ".join(_sidebar(client.get("/dashboard").get_data(as_text=True)).split())
    group = side.split("<summary>Monitoring")[0].split("<details")[-1]
    assert "open" in group                                                                           # opened so the "set up by" lines are visible
    assert "t07.example.com" in side and "t08.example.com" not in side and "+ 2 more in the overview" in side
    assert side.split("Monitoring <span")[1].startswith(' class="count">10</span>')                    # the count is the real total
