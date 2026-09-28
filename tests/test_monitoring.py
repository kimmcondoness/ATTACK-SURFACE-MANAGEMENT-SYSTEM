import os
import threading
import time
from datetime import datetime, timedelta

import pytest

from extensions import db
from models import Asset, AuditLog, AuthorizedTarget, MonitorEvent, Scan, User, Vulnerability
from scanner.base import ScanControl, ScannerResult
from scanner.nuclei_scanner import NucleiScanner
from services import job_registry, monitor_service, scan_runner, scan_service
from tests.conftest import login

NOW = datetime(2026, 9, 28, 12, 0, 0)
CONFIG = "[Config] "
DORK = "[Dork] "


def make_target(owner, domain="example.com", interval=None, last_run=None, authorized=True):
    target = AuthorizedTarget(domain=domain, owner_id=owner.id, authorized=authorized,
                              monitor_interval_days=interval, monitor_last_run_at=last_run)
    db.session.add(target)
    db.session.commit()
    return target


def make_asset(target, host, **fields):
    asset = Asset(target_id=target.id, subdomain=host, url=f"https://{host}", **fields)
    db.session.add(asset)
    db.session.commit()
    return asset


def finding(title, severity="medium"):
    return {"severity": severity, "cve": None, "title": title, "description": "d", "recommendation": "Fix it.\nRe-run."}


def events_of(target, kind=None):
    query = MonitorEvent.query.filter_by(target_id=target.id)
    if kind:
        query = query.filter_by(event_type=kind)
    return query.order_by(MonitorEvent.id).all()


@pytest.fixture
def live_job():
    """Register a job that stays 'running' until the test ends."""
    release, registered = threading.Event(), []

    def register(scan_id):
        thread = threading.Thread(target=release.wait, daemon=True)
        thread.start()
        job_registry.register(scan_id, thread, ScanControl())
        registered.append(scan_id)

    yield register
    release.set()
    for scan_id in registered:
        job_registry.unregister(scan_id)


# ============================================================ the schedule
def test_intervals_and_labels(app, analyst_user):
    target = make_target(analyst_user)
    for choice, days, label in (("daily", 1, "Daily"), ("weekly", 7, "Weekly"), ("monthly", 30, "Monthly"), ("off", None, "Off")):
        assert monitor_service.set_interval(target, choice, analyst_user.id) == days
        assert target.monitor_interval_days == days and monitor_service.interval_label(days) == label
    assert monitor_service.interval_label(3) == "Every 3 days"
    assert ("monitoring_updated", f"target_id={target.id} interval=off") in [(a.action, a.detail) for a in AuditLog.query.all()]


def test_an_unknown_interval_is_refused(app, analyst_user):
    target = make_target(analyst_user)
    with pytest.raises(ValueError):
        monitor_service.set_interval(target, "hourly", analyst_user.id)
    assert target.monitor_interval_days is None


def test_next_run_and_due(app, analyst_user):
    assert monitor_service.next_run_at(make_target(analyst_user, "a.example.com")) is None            # monitoring off

    weekly = make_target(analyst_user, "b.example.com", interval=7, last_run=NOW - timedelta(days=3))
    assert monitor_service.next_run_at(weekly) == NOW + timedelta(days=4)
    assert not monitor_service.is_due(weekly, NOW)
    assert monitor_service.is_due(weekly, NOW + timedelta(days=4))                                   # due exactly on time
    assert monitor_service.is_due(weekly, NOW + timedelta(days=5))

    never_scanned = make_target(analyst_user, "c.example.com", interval=1)
    assert monitor_service.is_due(never_scanned)                                                     # monitoring on, nothing yet


def test_the_last_scan_counts_when_the_target_predates_monitoring(app, analyst_user):
    target = make_target(analyst_user, interval=7)
    db.session.add(Scan(target_id=target.id, scan_type="asset_discovery", status="completed", started_by=analyst_user.id, started_at=NOW - timedelta(days=2)))
    db.session.commit()
    assert monitor_service.last_activity(target) == NOW - timedelta(days=2)
    assert monitor_service.next_run_at(target) == NOW + timedelta(days=5)


def test_run_due_starts_only_the_targets_whose_time_has_come(app, analyst_user):
    due = make_target(analyst_user, "due.example.com", interval=7, last_run=NOW - timedelta(days=8))
    make_target(analyst_user, "fresh.example.com", interval=7, last_run=NOW - timedelta(days=2))
    make_target(analyst_user, "off.example.com", interval=None, last_run=NOW - timedelta(days=90))
    make_target(analyst_user, "unauthorized.example.com", interval=1, last_run=NOW - timedelta(days=9), authorized=False)
    started = []

    result = monitor_service.run_due(app, now=NOW, starter=lambda a, t, uid: started.append((t.domain, uid)))

    assert result == [due.id] and started == [("due.example.com", analyst_user.id)]
    db.session.refresh(due)
    assert due.monitor_last_run_at == NOW                                                            # its timer restarted
    assert ("scheduled_scan_started", f"target_id={due.id} interval=weekly") in [(a.action, a.detail) for a in AuditLog.query.all()]


def test_a_target_can_only_be_claimed_once_per_period(app, analyst_user):
    target = make_target(analyst_user, interval=7, last_run=NOW - timedelta(days=8))
    stale_copy_of_the_same_target = db.session.get(AuthorizedTarget, target.id)

    assert monitor_service._claim(target, NOW) is True
    assert monitor_service._claim(stale_copy_of_the_same_target, NOW) is False                       # a second scheduler loses


def test_a_target_that_is_already_being_scanned_is_skipped(app, analyst_user, live_job):
    target = make_target(analyst_user, interval=1, last_run=NOW - timedelta(days=3))
    lead = Scan(target_id=target.id, scan_type="asset_discovery", status="running", started_by=analyst_user.id)
    db.session.add(lead)
    db.session.commit()
    live_job(lead.id)
    started = []

    assert monitor_service.run_due(app, now=NOW, starter=lambda *a: started.append(1)) == [] and started == []


def test_only_as_many_scans_start_as_the_concurrency_limit_allows(app, analyst_user, live_job):
    first = make_target(analyst_user, "a.example.com", interval=1, last_run=NOW - timedelta(days=5))
    second = make_target(analyst_user, "b.example.com", interval=1, last_run=NOW - timedelta(days=3))

    def starter(app_, target, user_id):
        lead = Scan(target_id=target.id, scan_type="asset_discovery", status="running", started_by=user_id)
        db.session.add(lead)
        db.session.commit()
        live_job(lead.id)

    assert monitor_service.run_due(app, now=NOW, starter=starter) == [first.id]                      # the longest-overdue goes first
    assert monitor_service.run_due(app, now=NOW, starter=starter) == []                              # the slot is still taken
    assert second.monitor_last_run_at is None or second.monitor_last_run_at < NOW


def test_start_chain_creates_the_lead_scan_registers_it_and_restarts_the_timer(app, analyst_user, monkeypatch):
    ran = []
    monkeypatch.setattr(scan_service, "run_scan_chain", lambda target, user_id, control, lead_scan=None: ran.append((target.domain, user_id, lead_scan.id)))
    target = make_target(analyst_user, interval=7)

    lead = scan_runner.start_chain(app, target, analyst_user.id)

    thread = job_registry._jobs[lead.id]["thread"] if lead.id in job_registry._jobs else None
    if thread:
        thread.join(5)
    assert lead.scan_type == "asset_discovery" and lead.started_by == analyst_user.id
    assert target.monitor_last_run_at is not None
    assert ran == [("example.com", analyst_user.id, lead.id)]
    assert not job_registry.is_running(lead.id)                                                      # unregistered when it finished


# ============================================================ scheduler thread
@pytest.fixture
def serving(app, monkeypatch):
    """Make the app look like a real (non-test) server so the scheduler is allowed to start."""
    monkeypatch.setitem(app.config, "TESTING", False)
    monkeypatch.setitem(app.config, "DEBUG", False)
    monkeypatch.setitem(app.config, "MONITOR_SCHEDULER_ENABLED", True)
    monkeypatch.setitem(app.config, "MONITOR_POLL_SECONDS", 0.05)
    yield app
    monitor_service.stop_scheduler()
    thread = monitor_service._scheduler_thread
    if thread:
        thread.join(3)


def test_the_scheduler_never_starts_during_tests_or_when_disabled(app, monkeypatch):
    assert monitor_service.start_scheduler(app) is None and monitor_service.start_scheduler(app, force=True) is None
    monkeypatch.setitem(app.config, "TESTING", False)
    monkeypatch.setitem(app.config, "MONITOR_SCHEDULER_ENABLED", False)
    assert monitor_service.start_scheduler(app, force=True) is None


def test_the_scheduler_checks_repeatedly_and_can_be_stopped(serving, monkeypatch):
    ticks = []
    monkeypatch.setattr(monitor_service, "run_due", lambda app_: ticks.append(1) or [])

    thread = monitor_service.start_scheduler(serving)

    assert thread is not None and thread.daemon
    deadline = time.time() + 5
    while len(ticks) < 3 and time.time() < deadline:
        time.sleep(0.02)
    assert len(ticks) >= 3
    assert monitor_service.start_scheduler(serving) is thread                                        # never a second one
    monitor_service.stop_scheduler()
    thread.join(3)
    assert not thread.is_alive()


def test_a_failing_tick_does_not_end_monitoring(serving, monkeypatch):
    calls = []

    def flaky(app_):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database hiccup")
        return []

    monkeypatch.setattr(monitor_service, "run_due", flaky)
    monitor_service.start_scheduler(serving)
    deadline = time.time() + 5
    while len(calls) < 3 and time.time() < deadline:
        time.sleep(0.02)
    assert len(calls) >= 3


def test_under_the_debug_reloader_only_the_serving_process_starts_it(serving, monkeypatch):
    monkeypatch.setitem(serving.config, "DEBUG", True)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    monkeypatch.setattr(monitor_service, "run_due", lambda app_: [])

    assert monitor_service.start_scheduler(serving) is None                                          # the reloader's parent process
    monkeypatch.setenv("WERKZEUG_RUN_MAIN", "true")
    thread = monitor_service.start_scheduler(serving)                                                # the reloaded, serving process
    assert thread is not None
    monitor_service.stop_scheduler()
    thread.join(3)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN")
    assert monitor_service.start_scheduler(serving, force=True) is not None                          # or on its first request


# ============================================================ assets
def test_first_discovery_records_assets_without_reporting_changes(app, analyst_user):
    target = make_target(analyst_user)
    created = monitor_service.sync_discovered_assets(
        target, [{"subdomain": "www.example.com", "url": "https://www.example.com"}, {"subdomain": "api.example.com", "url": "https://api.example.com"}],
        trustworthy=True, baseline=True)

    assert {a.subdomain for a in created} == {"www.example.com", "api.example.com"}
    assert all(a.status == "active" and a.last_seen_at and a.missed_runs == 0 for a in created)
    assert events_of(target) == []


def test_later_discoveries_report_new_assets_and_never_duplicate(app, analyst_user):
    target = make_target(analyst_user)
    make_asset(target, "www.example.com")
    found = [{"subdomain": "WWW.example.com", "url": "https://www.example.com"}, {"subdomain": "shop.example.com", "url": "https://shop.example.com"}]

    created = monitor_service.sync_discovered_assets(target, found, trustworthy=True, baseline=False)
    again = monitor_service.sync_discovered_assets(target, found, trustworthy=True, baseline=False)

    assert [a.subdomain for a in created] == ["shop.example.com"] and again == []
    assert Asset.query.filter_by(target_id=target.id).count() == 2                                   # case-insensitive, no duplicates
    assert [e.subject for e in events_of(target, "asset_new")] == ["shop.example.com"]


def test_an_asset_is_missing_only_after_two_misses_and_comes_back(app, analyst_user):
    target = make_target(analyst_user)
    keep, gone = make_asset(target, "www.example.com"), make_asset(target, "old.example.com")
    only_www = [{"subdomain": "www.example.com", "url": "https://www.example.com"}]

    monitor_service.sync_discovered_assets(target, only_www, trustworthy=True, baseline=False)
    assert (gone.status, gone.missed_runs) == ("active", 1) and events_of(target) == []              # one miss is not enough

    monitor_service.sync_discovered_assets(target, only_www, trustworthy=True, baseline=False)
    assert (gone.status, gone.missed_runs) == ("missing", 2)
    [event] = events_of(target, "asset_missing")
    assert event.subject == "old.example.com" and "2 discovery runs" in event.detail

    monitor_service.sync_discovered_assets(target, only_www, trustworthy=True, baseline=False)
    assert len(events_of(target, "asset_missing")) == 1                                              # reported once, not every run

    monitor_service.sync_discovered_assets(target, only_www + [{"subdomain": "old.example.com", "url": "https://old.example.com"}], trustworthy=True, baseline=False)
    assert (gone.status, gone.missed_runs) == ("active", 0)
    assert [e.subject for e in events_of(target, "asset_back")] == ["old.example.com"]
    assert keep.status == "active"


def test_an_unreliable_or_empty_discovery_never_marks_assets_missing(app, analyst_user):
    target = make_target(analyst_user)
    asset = make_asset(target, "www.example.com")

    for _ in range(3):
        monitor_service.sync_discovered_assets(target, [], trustworthy=False, baseline=False)                     # failed / empty run
        monitor_service.sync_discovered_assets(target, [{"subdomain": "x.example.com", "url": "u"}], trustworthy=False, baseline=False)  # sample data
    assert (asset.status, asset.missed_runs) == ("active", 0)
    assert [e.event_type for e in events_of(target)] == ["asset_new"]                                # only the one new host was reported


def test_the_root_domain_is_never_marked_missing(app, analyst_user):
    target = make_target(analyst_user)
    root = make_asset(target, "example.com")
    for _ in range(3):
        monitor_service.sync_discovered_assets(target, [{"subdomain": "www.example.com", "url": "u"}], trustworthy=True, baseline=False)
    assert root.status == "active"


# ============================================================ findings
def _asset(app_owner, domain="example.com"):
    target = make_target(app_owner, domain)
    return target, make_asset(target, f"www.{domain}")


def test_new_findings_are_reported_unless_it_is_the_baseline(app, analyst_user):
    target, asset = _asset(analyst_user)
    rec = monitor_service.reconcile_findings(target, asset, CONFIG, [finding(CONFIG + "A", "high"), finding(CONFIG + "B", "low")], baseline=True)
    assert len(rec.created) == 2 and events_of(target) == []

    later = monitor_service.reconcile_findings(target, asset, CONFIG, [finding(CONFIG + "A"), finding(CONFIG + "B"), finding(CONFIG + "C", "high")], baseline=False)
    assert [v.title for v in later.created] == [CONFIG + "C"]
    [event] = events_of(target, "finding_new")
    assert (event.subject, event.severity) == (CONFIG + "C", "high") and "www.example.com" in event.detail


def test_a_finding_that_is_no_longer_detected_is_marked_resolved_once(app, analyst_user):
    target, asset = _asset(analyst_user)
    monitor_service.reconcile_findings(target, asset, DORK, [finding(DORK + "env", "critical")], baseline=True)

    rec = monitor_service.reconcile_findings(target, asset, DORK, [], baseline=False)
    monitor_service.reconcile_findings(target, asset, DORK, [], baseline=False)

    vuln = Vulnerability.query.filter_by(asset_id=asset.id).one()
    assert vuln.status == "resolved" and [v.title for v in rec.resolved] == [DORK + "env"]
    [event] = events_of(target, "finding_resolved")
    assert event.severity == "critical" and "no longer detected" in event.detail.lower()


def test_in_progress_findings_are_also_resolved_but_false_positives_are_left_alone(app, analyst_user):
    target, asset = _asset(analyst_user)
    monitor_service.reconcile_findings(target, asset, CONFIG, [finding(CONFIG + "A"), finding(CONFIG + "B")], baseline=True)
    a, b = (Vulnerability.query.filter_by(title=CONFIG + t).one() for t in "AB")
    a.status, b.status = "in_progress", "false_positive"
    db.session.commit()

    monitor_service.reconcile_findings(target, asset, CONFIG, [], baseline=False)

    assert (a.status, b.status) == ("resolved", "false_positive")
    assert [e.subject for e in events_of(target, "finding_resolved")] == [CONFIG + "A"]


def test_a_resolved_finding_that_comes_back_is_reopened_not_duplicated(app, analyst_user):
    target, asset = _asset(analyst_user)
    monitor_service.reconcile_findings(target, asset, DORK, [finding(DORK + "env", "critical")], baseline=True)
    monitor_service.reconcile_findings(target, asset, DORK, [], baseline=False)

    rec = monitor_service.reconcile_findings(target, asset, DORK, [finding(DORK + "env", "critical")], baseline=False)

    assert Vulnerability.query.filter_by(asset_id=asset.id).count() == 1
    assert Vulnerability.query.filter_by(asset_id=asset.id).one().status == "open"
    assert [v.title for v in rec.reopened] == [DORK + "env"] and [e.event_type for e in events_of(target, "finding_reopened")] == ["finding_reopened"]


def test_a_false_positive_that_is_detected_again_stays_dismissed(app, analyst_user):
    target, asset = _asset(analyst_user)
    monitor_service.reconcile_findings(target, asset, CONFIG, [finding(CONFIG + "A")], baseline=True)
    vuln = Vulnerability.query.one()
    vuln.status = "false_positive"
    db.session.commit()

    monitor_service.reconcile_findings(target, asset, CONFIG, [finding(CONFIG + "A")], baseline=False)

    assert vuln.status == "false_positive" and events_of(target) == []


def test_reconciling_one_kind_of_check_leaves_other_findings_alone(app, analyst_user):
    target, asset = _asset(analyst_user)
    monitor_service.store_new_findings(target, asset, [finding("Possible CVE-2023-1 affecting nginx"), finding(DORK + "env")], baseline=True)

    monitor_service.reconcile_findings(target, asset, CONFIG, [], baseline=False)                    # a config run that finds nothing

    assert {v.title: v.status for v in Vulnerability.query.all()} == {"Possible CVE-2023-1 affecting nginx": "open", DORK + "env": "open"}


def test_storing_findings_never_duplicates_a_title_on_an_asset(app, analyst_user):
    target, asset = _asset(analyst_user)
    batch = [finding("Same"), finding("Same"), finding("Other")]
    assert len(monitor_service.store_new_findings(target, asset, batch, baseline=False)) == 2
    assert monitor_service.store_new_findings(target, asset, batch, baseline=False) == []
    assert Vulnerability.query.filter_by(asset_id=asset.id).count() == 2


# ============================================================ a whole story, chain after chain
class FakeSubfinder:
    hosts = []

    def is_available(self):
        return True

    def run(self, domain, control=None):
        return ScannerResult(success=True, source="real", data=[{"subdomain": h, "url": f"https://{h}"} for h in FakeSubfinder.hosts])


class FakeConfig:
    by_host, calls = {}, []

    def run(self, host, control=None):
        name = host.replace("https://", "")
        FakeConfig.calls.append(name)
        return ScannerResult(success=True, source="real", data=[finding(t, s) for t, s in FakeConfig.by_host.get(name, [])], raw_output="checked")


class FakeExposure:
    by_host = {}

    def run(self, host, control=None, bucket_domain=None):
        name = host.replace("https://", "")
        return ScannerResult(success=True, source="real", data=[finding(t, s) for t, s in FakeExposure.by_host.get(name, [])], raw_output="114 requests")


@pytest.fixture
def scripted_world(monkeypatch):
    FakeSubfinder.hosts, FakeConfig.by_host, FakeConfig.calls, FakeExposure.by_host = [], {}, [], {}
    monkeypatch.setattr(scan_service, "SubfinderScanner", FakeSubfinder)
    monkeypatch.setattr(scan_service, "ConfigScanner", FakeConfig)
    monkeypatch.setattr(scan_service, "ExposureScanner", FakeExposure)
    monkeypatch.setattr(scan_service, "run_port_discovery", lambda *a, **k: None)
    monkeypatch.setattr(scan_service, "_cve_lookup_findings", lambda asset, control=None: [])
    monkeypatch.setattr(NucleiScanner, "is_available", lambda self: False)


def chain(target, owner):
    return scan_service.run_scan_chain(target, owner.id, ScanControl())


def summary(target):
    return [(e.event_type, e.subject) for e in events_of(target)]


def test_a_target_monitored_over_four_scans_reports_exactly_what_changed(app, analyst_user, scripted_world):
    target = make_target(analyst_user, interval=7)
    CSP, ENV = CONFIG + "Missing security header: Content-Security-Policy", DORK + "Exposed environment file: /.env"

    # scan 1: the baseline. Everything is recorded, nothing is announced as a change.
    FakeSubfinder.hosts = ["www.example.com", "api.example.com"]
    FakeConfig.by_host = {"www.example.com": [(CSP, "medium")]}
    chain(target, analyst_user)
    assert summary(target) == []
    assert {a.subdomain for a in Asset.query.filter_by(target_id=target.id)} == {"example.com", "www.example.com", "api.example.com"}
    assert [v.title for v in Vulnerability.query.all()] == [CSP]

    # scan 2: a new host appears, api is missed once, and an exposed .env shows up
    FakeSubfinder.hosts = ["www.example.com", "new.example.com"]
    FakeExposure.by_host = {"www.example.com": [(ENV, "critical")]}
    chain(target, analyst_user)
    assert summary(target) == [("asset_new", "new.example.com"), ("finding_new", ENV)]
    assert Asset.query.filter_by(subdomain="api.example.com").one().status == "active"               # only one miss so far

    # scan 3: api missed a second time, the .env is removed and the header is added
    FakeSubfinder.hosts = ["www.example.com", "new.example.com"]
    FakeExposure.by_host, FakeConfig.by_host = {}, {}
    chain(target, analyst_user)
    assert summary(target)[2:] == [("asset_missing", "api.example.com"), ("finding_resolved", CSP), ("finding_resolved", ENV)] or \
        sorted(summary(target)[2:]) == sorted([("asset_missing", "api.example.com"), ("finding_resolved", CSP), ("finding_resolved", ENV)])
    assert {v.title: v.status for v in Vulnerability.query.all()} == {CSP: "resolved", ENV: "resolved"}

    # scan 4: a host discovery says is gone is no longer scanned, and nothing new is announced
    FakeConfig.calls.clear()
    before = len(events_of(target))
    chain(target, analyst_user)
    assert "api.example.com" not in FakeConfig.calls and "www.example.com" in FakeConfig.calls
    assert len(events_of(target)) == before


def test_the_baseline_scan_of_a_brand_new_target_announces_nothing_even_across_many_assets(app, analyst_user, scripted_world):
    target = make_target(analyst_user, interval=1)
    FakeSubfinder.hosts = [f"h{i}.example.com" for i in range(4)]
    FakeConfig.by_host = {f"h{i}.example.com": [(CONFIG + "X", "medium")] for i in range(4)}
    chain(target, analyst_user)
    assert events_of(target) == [] and Vulnerability.query.count() == 4


def test_a_sample_data_discovery_never_creates_or_hides_real_changes(app, analyst_user, scripted_world, monkeypatch):
    class Sample(FakeSubfinder):
        def run(self, domain, control=None):
            return ScannerResult(success=True, source="mock", data=[{"subdomain": "www.example.com", "url": "u"}])

    target = make_target(analyst_user, interval=1)
    FakeSubfinder.hosts = ["www.example.com", "api.example.com"]
    chain(target, analyst_user)
    monkeypatch.setattr(scan_service, "SubfinderScanner", Sample)
    for _ in range(3):
        chain(target, analyst_user)
    assert Asset.query.filter_by(subdomain="api.example.com").one().status == "active"               # sample data cannot make it 'missing'
    assert events_of(target) == []


# ============================================================ the vulnerability scan itself
def test_an_unreachable_host_skips_the_config_checks_and_does_not_resolve_anything(app, analyst_user, monkeypatch):
    class Down:
        def run(self, host, control=None):
            return ScannerResult(success=True, source="real", raw_output="unreachable")

    monkeypatch.setattr(scan_service, "ConfigScanner", Down)
    monkeypatch.setattr(scan_service, "_cve_lookup_findings", lambda asset, control=None: [])
    monkeypatch.setattr(NucleiScanner, "is_available", lambda self: False)
    target, asset = _asset(analyst_user)
    monitor_service.reconcile_findings(target, asset, CONFIG, [finding(CONFIG + "A")], baseline=True)

    scan = scan_service.run_vulnerability_scan(target, asset, analyst_user.id)

    assert scan.status == "completed" and "did not answer" in scan.result_summary
    assert Vulnerability.query.one().status == "open"                                                # a host that is down proves nothing was fixed


def test_stopping_during_the_vulnerability_scan_records_it_as_stopped(app, analyst_user, monkeypatch):
    monkeypatch.setattr(NucleiScanner, "is_available", lambda self: False)
    target, asset = _asset(analyst_user)
    control = ScanControl()
    control.request_stop()

    scan = scan_service.run_vulnerability_scan(target, asset, analyst_user.id, control=control)

    assert scan.status == "stopped"


def test_nuclei_findings_are_stored_once_and_a_failing_nuclei_does_not_lose_the_config_results(app, analyst_user, monkeypatch, scripted_world):
    class Nuclei:
        def is_available(self):
            return True

        def run(self, host, control=None):
            return ScannerResult(success=True, source="real", data=[finding("Nuclei template hit", "high")])

    monkeypatch.setattr(scan_service, "NucleiScanner", Nuclei)
    FakeConfig.by_host = {"www.example.com": [(CONFIG + "A", "low")]}
    target, asset = _asset(analyst_user)

    scan_service.run_vulnerability_scan(target, asset, analyst_user.id)
    scan_service.run_vulnerability_scan(target, asset, analyst_user.id)
    assert sorted(v.title for v in Vulnerability.query.all()) == sorted(["Nuclei template hit", CONFIG + "A"])

    class Broken(Nuclei):
        def run(self, host, control=None):
            return ScannerResult(success=False, source="real", error="template download failed")

    monkeypatch.setattr(scan_service, "NucleiScanner", Broken)
    scan = scan_service.run_vulnerability_scan(target, asset, analyst_user.id)
    assert scan.status == "completed" and "Nuclei failed" in scan.result_summary


# ============================================================ alerts
def _alert_setup(app, analyst_user, monkeypatch, interval=7, enabled=True):
    monkeypatch.setitem(app.config, "MONITOR_ALERT_EMAILS", enabled)
    sent = []
    monkeypatch.setattr("utils.mailer.send_email", lambda to, subject, body: sent.append((to, subject, body)) or True)
    return make_target(analyst_user, interval=interval), sent


def test_notable_events_are_new_or_missing_assets_and_serious_findings():
    def ev(kind, severity=None):
        return MonitorEvent(target_id=1, event_type=kind, subject="s", severity=severity)

    events = [ev("asset_new"), ev("asset_missing"), ev("asset_back"), ev("finding_new", "critical"), ev("finding_new", "high"),
              ev("finding_new", "medium"), ev("finding_new", "low"), ev("finding_reopened", "high"), ev("finding_reopened", "low"), ev("finding_resolved", "critical")]
    assert [(e.event_type, e.severity) for e in monitor_service.notable(events)] == [
        ("asset_new", None), ("asset_missing", None), ("finding_new", "critical"), ("finding_new", "high"), ("finding_reopened", "high")]


def test_the_owner_gets_one_email_listing_what_changed(app, analyst_user, monkeypatch):
    target, sent = _alert_setup(app, analyst_user, monkeypatch)
    since = datetime.utcnow() - timedelta(minutes=1)
    monitor_service.record_event(target.id, "asset_new", "new.example.com")
    monitor_service.record_event(target.id, "finding_new", "[Dork] Exposed environment file: /.env", severity="critical")
    monitor_service.record_event(target.id, "finding_new", "Minor thing", severity="low")

    assert monitor_service.send_digest(app, target.id, since) is True

    [(to, subject, body)] = sent
    assert to == analyst_user.email and "2 change(s)" in subject and "example.com" in subject
    assert "New asset: new.example.com" in body and "Exposed environment file" in body and "[critical]" in body
    assert "Minor thing" not in body
    assert "monitor_alert_sent" in [a.action for a in AuditLog.query.all()]


def test_no_email_when_nothing_notable_or_monitoring_or_alerts_are_off(app, analyst_user, monkeypatch):
    target, sent = _alert_setup(app, analyst_user, monkeypatch)
    since = datetime.utcnow() - timedelta(minutes=1)
    monitor_service.record_event(target.id, "finding_resolved", "Fixed thing", severity="high")
    assert monitor_service.send_digest(app, target.id, since) is False                               # a fix is good news, not an alert

    monitor_service.record_event(target.id, "asset_new", "new.example.com")
    assert monitor_service.send_digest(app, target.id, datetime.utcnow() + timedelta(minutes=1)) is False   # nothing since then
    target.monitor_interval_days = None
    db.session.commit()
    assert monitor_service.send_digest(app, target.id, since) is False                               # monitoring is off for this target
    target.monitor_interval_days = 7
    db.session.commit()
    monkeypatch.setitem(app.config, "MONITOR_ALERT_EMAILS", False)
    assert monitor_service.send_digest(app, target.id, since) is False                               # alerts switched off
    assert sent == []


def test_a_long_digest_is_cut_off_politely(app, analyst_user, monkeypatch):
    target, sent = _alert_setup(app, analyst_user, monkeypatch)
    since = datetime.utcnow() - timedelta(minutes=1)
    for i in range(20):
        monitor_service.record_event(target.id, "asset_new", f"h{i}.example.com")
    monitor_service.send_digest(app, target.id, since)
    assert "...and 5 more." in sent[0][2] and sent[0][2].count("New asset:") == 15


def test_a_failed_send_is_logged_not_raised(app, analyst_user, monkeypatch):
    target, _ = _alert_setup(app, analyst_user, monkeypatch)
    monkeypatch.setattr("utils.mailer.send_email", lambda *a: False)
    monitor_service.record_event(target.id, "asset_new", "x.example.com")
    assert monitor_service.send_digest(app, target.id, datetime.utcnow() - timedelta(minutes=1)) is False
    assert "monitor_alert_not_sent" in [a.action for a in AuditLog.query.all()]


def test_a_finished_chain_sends_the_alert_and_a_crashing_alert_never_breaks_it(app, analyst_user, monkeypatch):
    target = make_target(analyst_user, interval=7)
    lead = Scan(target_id=target.id, scan_type="asset_discovery", status="pending", started_by=analyst_user.id)
    db.session.add(lead)
    db.session.commit()
    monkeypatch.setattr(scan_service, "run_scan_chain", lambda *a, **k: None)
    digests = []
    monkeypatch.setattr(monitor_service, "send_digest", lambda app_, target_id, since: digests.append(target_id))

    scan_runner.run_chain_in_background(app, target.id, analyst_user.id, ScanControl(), lead.id)
    assert digests == [target.id]

    def boom(*args, **kwargs):
        raise RuntimeError("smtp exploded")

    monkeypatch.setattr(monitor_service, "send_digest", boom)
    scan_runner.run_chain_in_background(app, target.id, analyst_user.id, ScanControl(), lead.id)   # must not raise


def test_a_crashed_chain_marks_the_lead_scan_failed(app, analyst_user, monkeypatch):
    target = make_target(analyst_user)
    lead = Scan(target_id=target.id, scan_type="asset_discovery", status="running", started_by=analyst_user.id)
    db.session.add(lead)
    db.session.commit()

    def crash(*args, **kwargs):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scan_service, "run_scan_chain", crash)
    scan_runner.run_chain_in_background(app, target.id, analyst_user.id, ScanControl(), lead.id)

    db.session.refresh(lead)
    assert lead.status == "failed" and "scanner exploded" in lead.result_summary


# ============================================================ the web pages
def _other_analyst():
    user = User(username="other", email="other@example.com", role="cybersecurity_analyst")
    user.set_password("OtherPass#123")
    db.session.add(user)
    db.session.commit()
    return user


def _set(client, target, interval, **extra):
    return client.post(f"/workspace/monitoring/{target.id}", data={"interval": interval, **extra})


def test_an_analyst_can_turn_monitoring_on_and_off(client, analyst_user):
    target = make_target(analyst_user)
    login(client, "analyst", "AnalystPass123!")

    assert _set(client, target, "weekly").status_code == 302
    assert db.session.get(AuthorizedTarget, target.id).monitor_interval_days == 7
    assert "re-scanned automatically: weekly" in client.get("/dashboard/details").get_data(as_text=True)

    _set(client, target, "off")
    assert db.session.get(AuthorizedTarget, target.id).monitor_interval_days is None


def test_an_invalid_choice_changes_nothing(client, analyst_user):
    target = make_target(analyst_user, interval=7)
    login(client, "analyst", "AnalystPass123!")

    _set(client, target, "every-second")

    assert db.session.get(AuthorizedTarget, target.id).monitor_interval_days == 7
    assert "Choose one of" in client.get("/dashboard/details").get_data(as_text=True)


def test_nobody_can_change_monitoring_on_a_target_that_is_not_theirs(client, analyst_user):
    target = make_target(analyst_user, interval=7)
    _other_analyst()
    login(client, "other", "OtherPass#123")

    _set(client, target, "daily")

    assert db.session.get(AuthorizedTarget, target.id).monitor_interval_days == 7


def test_threat_intel_and_anonymous_users_cannot_change_monitoring(client, analyst_user):
    target = make_target(analyst_user, interval=7)
    assert _set(client, target, "off").status_code == 302 and "login" in _set(client, target, "off").headers["Location"]

    intel = User(username="intel", email="intel@example.com", role="threat_intel_analyst")
    intel.set_password("IntelPass#123")
    db.session.add(intel)
    db.session.commit()
    login(client, "intel", "IntelPass#123")
    _set(client, target, "off")
    assert db.session.get(AuthorizedTarget, target.id).monitor_interval_days == 7


def test_an_admin_may_change_anyones_target(client, admin_user, analyst_user):
    target = make_target(analyst_user)
    login(client, "admin", "AdminPass123!")
    _set(client, target, "monthly")
    assert db.session.get(AuthorizedTarget, target.id).monitor_interval_days == 30


def test_the_dashboard_shows_the_schedule_and_the_changes(client, analyst_user):
    target = make_target(analyst_user, interval=7, last_run=datetime.utcnow() - timedelta(days=1))
    make_target(analyst_user, "quiet.example.com")
    monitor_service.record_event(target.id, "asset_new", "new.example.com", detail="Found by subdomain discovery.")
    monitor_service.record_event(target.id, "finding_new", "[Dork] Exposed environment file: /.env", severity="critical")
    monitor_service.record_event(target.id, "finding_resolved", "[Config] Missing security header: Content-Security-Policy", severity="medium")
    login(client, "analyst", "AnalystPass123!")

    html = client.get("/dashboard/details").get_data(as_text=True)

    assert "Changes detected" in html and "3 recorded" in html
    for label in ("New asset", "New finding", "Fixed"):
        assert f">{label}<" in html
    assert "new.example.com" in html and "Found by subdomain discovery." in html
    assert 'aria-label="Automatic re-scan schedule for example.com"' in html
    assert '<option value="weekly" selected>Weekly</option>' in html
    assert html.count("Next scan:") == 1                                                             # only the monitored target shows one
    assert "Monitoring</th>" in html


def test_the_changes_panel_follows_the_selected_target(client, analyst_user):
    busy, quiet = make_target(analyst_user, "busy.example.com"), make_target(analyst_user, "quiet.example.com")
    monitor_service.record_event(busy.id, "asset_new", "only-on-busy.example.com")
    login(client, "analyst", "AnalystPass123!")

    assert "only-on-busy.example.com" in client.get(f"/dashboard/details?target_id={busy.id}").get_data(as_text=True)
    assert "only-on-busy.example.com" not in client.get(f"/dashboard/details?target_id={quiet.id}").get_data(as_text=True)


def test_an_empty_changes_panel_explains_how_to_get_changes(client, analyst_user):
    make_target(analyst_user)
    login(client, "analyst", "AnalystPass123!")
    html = client.get("/dashboard/details").get_data(as_text=True)
    assert "No changes yet." in html and "Turn on monitoring" in html


def test_one_analysts_changes_are_never_shown_to_another(client, analyst_user):
    target = make_target(analyst_user)
    monitor_service.record_event(target.id, "asset_new", "secret-host.example.com")
    _other_analyst()
    login(client, "other", "OtherPass#123")
    assert "secret-host.example.com" not in client.get("/dashboard/details").get_data(as_text=True)


def test_the_first_request_starts_the_scheduler_exactly_once(app, client, monkeypatch):
    calls = []
    monkeypatch.setattr(monitor_service, "start_scheduler", lambda app_, force=False: calls.append(force))
    app.extensions.pop("monitor_scheduler_started", None)

    client.get("/api/health")
    client.get("/api/health")

    assert calls == [True]


def test_deleting_a_target_removes_its_events(app, analyst_user):
    target = make_target(analyst_user)
    monitor_service.record_event(target.id, "asset_new", "x.example.com")
    db.session.delete(target)
    db.session.commit()
    assert MonitorEvent.query.count() == 0
