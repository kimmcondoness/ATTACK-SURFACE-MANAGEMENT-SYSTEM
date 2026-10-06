"""Continuous monitoring: re-scan targets on a schedule and notice what changed.

Three jobs live here.

1. The schedule. A target can be re-scanned daily, weekly or monthly. `run_due` starts the
   chain for every target whose time has come; a background thread (see start_scheduler)
   calls it every minute. A target is claimed with one atomic UPDATE before it is started,
   so even two processes running a scheduler can never scan the same target twice.

2. Change detection. Every scan is compared with what was known before, and each
   difference is stored as a MonitorEvent (the "Changes detected" panel):
     * assets: new, missing (not returned by two discovery runs in a row) and back
     * findings: new, fixed (a deterministic check no longer finds it) and reopened
   The very first scan of a target is a baseline: everything found is recorded but nothing
   is reported as a "change".

3. Alerts. When a monitored target changes in a way that matters, its owner gets one email.

4. The record. Monitoring runs on the server, not in anyone's browser, so it carries on while
   users are signed out. Two tables prove it: `monitor_runs` (every scan that counts as
   monitoring, whoever or whatever started it) and `monitor_heartbeat` (the scheduler's pulse).
   When a user signs back in, `away_summary` tells them what happened while they were gone.
"""

import logging
import os
import re
import threading
from collections import Counter, namedtuple
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import or_

from extensions import db
from models import (
    MONITOR_INTERVALS,
    ROLE_IT_ADMIN,
    ROLE_THREAT_INTEL,
    Asset,
    AuditLog,
    AuthorizedTarget,
    MonitorEvent,
    MonitorHeartbeat,
    MonitorRun,
    Scan,
    User,
    Vulnerability,
)
from services import job_registry, vulnerability_service
from services.user_admin_service import display_name
from utils.audit import log_action

log = logging.getLogger(__name__)

MISSES_BEFORE_MISSING = 2
LIVE_STATUSES = ("open", "in_progress")
ALERT_SEVERITIES = ("critical", "high")
_INTERVAL_LABELS = {1: "Daily", 7: "Weekly", 30: "Monthly"}
EVENT_LABELS = {
    "asset_new": "New asset",
    "asset_missing": "Asset missing",
    "asset_back": "Asset back",
    "finding_new": "New finding",
    "finding_resolved": "Fixed",
    "finding_reopened": "Reopened",
}

_RUN_TERMINAL = ("completed", "failed", "stopped", "interrupted")
_UNFINISHED_SCANS = ("pending", "running", "paused")
# How each kind of change reads in a run's one-line summary: (singular, plural).
_SUMMARY_WORDS = {
    "asset_new": ("new asset", "new assets"),
    "asset_missing": ("missing asset", "missing assets"),
    "asset_back": ("asset back", "assets back"),
    "finding_new": ("new finding", "new findings"),
    "finding_resolved": ("fixed", "fixed"),
    "finding_reopened": ("reopened", "reopened"),
}

Reconciled = namedtuple("Reconciled", "created resolved reopened")


def utcnow() -> datetime:
    return datetime.utcnow()


# ------------------------------------------------------------------ the schedule
def interval_label(days: Optional[int]) -> str:
    if not days:
        return "Off"
    return _INTERVAL_LABELS.get(days, f"Every {days} days")


def set_interval(target: AuthorizedTarget, choice: str, actor_id: int) -> Optional[int]:
    """Turn monitoring on ("daily", "weekly", "monthly") or off ("off")."""
    if choice not in MONITOR_INTERVALS:
        raise ValueError(f"Choose one of: {', '.join(MONITOR_INTERVALS)}.")
    days = MONITOR_INTERVALS[choice]
    previous = target.monitor_interval_days
    target.monitor_interval_days = days
    if days is None:
        target.monitor_set_by = target.monitor_set_at = None
    elif days != previous or target.monitor_set_by is None:   # saving the same schedule again changes nothing
        target.monitor_set_by, target.monitor_set_at = actor_id, utcnow()
    db.session.commit()
    log_action(actor_id, "monitoring_updated", detail=f"target_id={target.id} interval={choice}")
    return target.monitor_interval_days


def last_activity(target: AuthorizedTarget) -> Optional[datetime]:
    """When this target was last scanned: the last chain start, else its newest scan."""
    if target.monitor_last_run_at:
        return target.monitor_last_run_at
    newest = Scan.query.filter_by(target_id=target.id).order_by(Scan.started_at.desc()).first()
    return newest.started_at if newest else None


def next_run_at(target: AuthorizedTarget) -> Optional[datetime]:
    """When the next automatic scan is due, or None if monitoring is off."""
    if not target.monitor_interval_days:
        return None
    last = last_activity(target)
    return last + timedelta(days=target.monitor_interval_days) if last else utcnow()


def is_due(target: AuthorizedTarget, now: Optional[datetime] = None) -> bool:
    due = next_run_at(target)
    return bool(due and due <= (now or utcnow()))


def target_is_scanning(target_id: int) -> bool:
    leads = (
        Scan.query.filter_by(target_id=target_id, scan_type="asset_discovery")
        .order_by(Scan.id.desc())
        .limit(5)
        .all()
    )
    return any(job_registry.is_running(lead.id) for lead in leads)


def _claim(target: AuthorizedTarget, now: datetime) -> bool:
    """Take the target for this scheduler tick. One atomic UPDATE, so of any number of
    schedulers only one wins, and the target's timer restarts as it is claimed."""
    threshold = now - timedelta(days=target.monitor_interval_days)
    claimed = (
        AuthorizedTarget.query.filter(
            AuthorizedTarget.id == target.id,
            or_(AuthorizedTarget.monitor_last_run_at.is_(None), AuthorizedTarget.monitor_last_run_at <= threshold),
        ).update({"monitor_last_run_at": now}, synchronize_session=False)
    )
    db.session.commit()
    return claimed == 1


def run_due(app, now: Optional[datetime] = None, starter=None) -> list:
    """Start the scan chain for every monitored target that is due. Returns their ids."""
    if starter is None:
        from functools import partial

        from services.scan_runner import start_chain

        starter = partial(start_chain, trigger="scheduled")

    now = now or utcnow()
    limit = app.config.get("MONITOR_MAX_CONCURRENT_SCANS", 1)
    monitored = AuthorizedTarget.query.filter(
        AuthorizedTarget.monitor_interval_days.isnot(None), AuthorizedTarget.authorized.is_(True)
    ).all()
    due = sorted((t for t in monitored if is_due(t, now)), key=lambda t: next_run_at(t))

    started = []
    for target in due:
        if job_registry.running_count() >= limit:
            break
        if target_is_scanning(target.id) or not _claim(target, now):
            continue
        starter(app, target, target.owner_id)
        log_action(target.owner_id, "scheduled_scan_started", detail=f"target_id={target.id} interval={interval_label(target.monitor_interval_days).lower()}")
        started.append(target.id)
    return started


# --------------------------------------------------------------------- scheduler
_scheduler_lock = threading.Lock()
_scheduler_thread: Optional[threading.Thread] = None
_scheduler_stop = threading.Event()


def _tick(app, started_at: datetime):
    """One scheduler check: start whatever is due, then write the heartbeat. The heartbeat is
    written even when the check failed (carrying the error), so "alive but struggling" can be told
    apart from "not running at all"."""
    error = None
    try:
        with app.app_context():
            try:
                run_due(app)
            except Exception as exc:   # noqa: BLE001 - one bad tick must never end monitoring
                error = f"{type(exc).__name__}: {exc}"
                db.session.rollback()
                app.logger.exception("Monitoring scheduler tick failed")
            record_heartbeat(started_at, error)
    except Exception:   # noqa: BLE001 - not even the heartbeat may stop the loop
        app.logger.exception("Monitoring heartbeat could not be written")


def _scheduler_loop(app):
    poll = app.config.get("MONITOR_POLL_SECONDS", 60)
    started_at = utcnow()
    while True:   # check straight away (catching up after downtime), then every `poll` seconds
        _tick(app, started_at)
        if _scheduler_stop.wait(poll):
            break


def start_scheduler(app, force: bool = False):
    """Start the background scheduler (once per process). Under the Flask debug reloader the
    parent process would start a second one, so there it waits for the first request, which
    only the serving process ever receives (`force`). Returns the thread, or None."""
    global _scheduler_thread
    if app.config.get("TESTING") or not app.config.get("MONITOR_SCHEDULER_ENABLED", True):
        return None
    serving_process = os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug
    if not (serving_process or force):
        return None
    with _scheduler_lock:
        if _scheduler_thread and _scheduler_thread.is_alive():
            return _scheduler_thread
        try:   # before anything new can start: close what the previous process left half-done
            with app.app_context():
                recovered = recover_interrupted()
            if recovered:
                app.logger.warning("Monitoring: %s scan(s) were interrupted by the last shutdown and were closed.", recovered)
        except Exception:   # noqa: BLE001 - e.g. a brand-new database that has no tables yet
            app.logger.exception("Monitoring could not check for interrupted scans")
        _scheduler_stop.clear()
        _scheduler_thread = threading.Thread(target=_scheduler_loop, args=(app,), daemon=True, name="monitor-scheduler")
        _scheduler_thread.start()
        app.logger.info("Continuous monitoring scheduler started (checks every %ss).", app.config.get("MONITOR_POLL_SECONDS", 60))
        return _scheduler_thread


def stop_scheduler():
    _scheduler_stop.set()


# ------------------------------------------------------------------- the record
_ENGINE_LABELS = {
    "active": "Monitoring engine active",
    "idle": "Monitoring engine idle",
    "stalled": "Monitoring engine not responding",
    "waiting": "Monitoring engine has not reported yet",
    "disabled": "Monitoring engine switched off",
}
SEEN_THROTTLE_SECONDS = 60


def record_heartbeat(started_at: datetime, error: Optional[str] = None):
    """Write the scheduler's pulse (see MonitorHeartbeat). Called after every check."""
    beat = db.session.get(MonitorHeartbeat, 1)
    if beat is None:
        beat = MonitorHeartbeat(id=1)
        db.session.add(beat)
    beat.started_at = started_at
    beat.last_tick_at = utcnow()
    beat.pid = os.getpid()
    beat.last_error = error[:255] if error else None
    db.session.commit()


def engine_status(app, now: Optional[datetime] = None, target_ids=None) -> dict:
    """Is monitoring alive? Read from the heartbeat the scheduler leaves in the database, so the
    answer is the same whoever asks, and whether or not anyone is signed in.

    The engine only counts as "active" while some user has monitoring turned on; with nothing to
    monitor it is "idle" (still responding, but with no work). `target_ids` is the viewer's own
    scope, used to say how many of the monitored targets are theirs and how many belong to others."""
    now = now or utcnow()
    poll = app.config.get("MONITOR_POLL_SECONDS", 60)
    beat = db.session.get(MonitorHeartbeat, 1)
    last_tick = beat.last_tick_at if beat else None
    age = max(0, int((now - last_tick).total_seconds())) if last_tick else None

    monitored = AuthorizedTarget.query.filter(
        AuthorizedTarget.monitor_interval_days.isnot(None), AuthorizedTarget.authorized.is_(True)
    )
    total = monitored.count()
    yours = total if target_ids is None else (monitored.filter(AuthorizedTarget.id.in_(list(target_ids))).count() if target_ids else 0)

    if age is not None and age <= poll * 3 + 30:   # tolerates a couple of slow checks
        state = "active" if total else "idle"
    elif not app.config.get("MONITOR_SCHEDULER_ENABLED", True):
        state = "disabled"
    else:
        state = "stalled" if last_tick else "waiting"

    return {
        "state": state,
        "label": _ENGINE_LABELS[state],
        "last_check_at": last_tick,
        "age_seconds": age,
        "started_at": beat.started_at if beat else None,
        "poll_seconds": poll,
        "monitored_targets": total,
        "your_monitored_targets": yours,
        "other_monitored_targets": total - yours,
        "running_scans": job_registry.running_count(),
        "last_error": beat.last_error if beat else None,
    }


def public_status(status: dict) -> dict:
    """`engine_status` as plain JSON (timestamps are ISO-8601, UTC)."""
    return {key: (f"{value.isoformat()}Z" if isinstance(value, datetime) else value) for key, value in status.items()}


def start_run(target: AuthorizedTarget, lead_scan: Scan, trigger: str) -> Optional[MonitorRun]:
    """Open the monitoring record for a scan chain that is starting. Only a scheduled chain, or a
    manual one on a monitored target, counts as monitoring. The caller commits."""
    if trigger != "scheduled" and not target.monitor_interval_days:
        return None
    run = MonitorRun(target_id=target.id, lead_scan_id=lead_scan.id, trigger=trigger, status="running", started_at=utcnow())
    db.session.add(run)
    return run


def finish_run(lead_scan_id: int, status: Optional[str] = None, alert_sent: bool = False) -> Optional[MonitorRun]:
    """Close the monitoring record of the chain led by `lead_scan_id`: how it ended, how many
    changes it found and whether the owner was emailed. A chain that was never recorded is skipped."""
    run = MonitorRun.query.filter_by(lead_scan_id=lead_scan_id).order_by(MonitorRun.id.desc()).first()
    if run is None or run.status in _RUN_TERMINAL:
        return run
    lead = db.session.get(Scan, lead_scan_id)
    if status is None:
        status = lead.status if lead and lead.status in ("failed", "stopped") else "completed"

    run.status = status
    run.finished_at = utcnow()
    run.alert_sent = bool(alert_sent)
    events = MonitorEvent.query.filter(MonitorEvent.target_id == run.target_id, MonitorEvent.created_at >= run.started_at).all()
    run.changes = len(events)
    run.summary = _run_summary(run, events, lead)
    db.session.commit()
    return run


def _run_summary(run: MonitorRun, events: list, lead: Optional[Scan]) -> str:
    if run.status == "failed":
        return ((lead.result_summary if lead else None) or "The scan failed.")[:500]
    prefix = "Stopped early. " if run.status == "stopped" else ""
    if is_first_chain(run.target_id, run.lead_scan_id):
        return prefix + "Baseline recorded. The first scan only sets the starting point, so no changes are reported."
    if not events:
        return prefix + "No changes since the previous scan."
    counts = Counter(e.event_type for e in events)
    parts = [f"{counts[kind]} {one if counts[kind] == 1 else many}" for kind, (one, many) in _SUMMARY_WORDS.items() if counts[kind]]
    text = ", ".join(parts)
    return prefix + text[:1].upper() + text[1:]


def recent_runs(target_ids, limit: int = 50) -> list:
    if not target_ids:
        return []
    return (
        MonitorRun.query.filter(MonitorRun.target_id.in_(target_ids))
        .order_by(MonitorRun.started_at.desc(), MonitorRun.id.desc())
        .limit(limit)
        .all()
    )


def activity_totals(target_ids, days: int = 7, now: Optional[datetime] = None) -> dict:
    """How much monitoring has done lately: scheduled scans started and changes noticed."""
    since = (now or utcnow()) - timedelta(days=days)
    if not target_ids:
        return {"days": days, "scheduled_runs": 0, "changes": 0}
    return {
        "days": days,
        "scheduled_runs": MonitorRun.query.filter(
            MonitorRun.target_id.in_(target_ids), MonitorRun.trigger == "scheduled", MonitorRun.started_at >= since
        ).count(),
        "changes": MonitorEvent.query.filter(MonitorEvent.target_id.in_(target_ids), MonitorEvent.created_at >= since).count(),
    }


def recover_interrupted() -> int:
    """Close the scans and monitoring runs a previous process left unfinished.

    Scans live on background threads, so a restart or crash ends them without a word and they would
    otherwise sit in "running" for ever. Called as the scheduler starts, when nothing can be running
    in this process yet. A scheduled run that was cut short is rescheduled to start at the next check,
    so a restart does not cost a monitored target a whole interval (a monthly target would otherwise
    wait a month). Returns how many scans were closed."""
    if job_registry.running_count():
        return 0   # something really is running here: leave it alone
    now = utcnow()
    stuck = Scan.query.filter(Scan.status.in_(_UNFINISHED_SCANS)).all()
    for scan in stuck:
        scan.status = "failed"
        scan.completed_at = now
        scan.result_summary = "Interrupted: the server stopped before this scan finished."

    for run in MonitorRun.query.filter_by(status="running").all():
        run.status = "interrupted"
        run.finished_at = now
        run.summary = "The server stopped before this scan finished."
        target = db.session.get(AuthorizedTarget, run.target_id)
        if run.trigger == "scheduled" and target and target.monitor_interval_days:
            run.summary += " It will be started again at the next check."
            target.monitor_last_run_at = now - timedelta(days=target.monitor_interval_days)
    db.session.commit()
    return len(stuck)


def visible_target_ids(user) -> list:
    """The targets whose monitoring this user may see: their own, or all of them for the roles
    that work across the organisation (admin, threat intelligence)."""
    query = AuthorizedTarget.query.with_entities(AuthorizedTarget.id)
    if user.role not in (ROLE_IT_ADMIN, ROLE_THREAT_INTEL):
        query = query.filter(AuthorizedTarget.owner_id == user.id)
    return [row.id for row in query.all()]


_AUDIT_DETAIL = re.compile(r"target_id=(\d+) interval=(\w+)")


def _earlier_setters(target_ids) -> dict:
    """{target_id: (user_id, when)} for monitoring that was turned on before `monitor_set_by` was
    recorded, worked out from the audit log: the last person to switch it on or change its schedule."""
    wanted, found = set(target_ids), {}
    for entry in AuditLog.query.filter_by(action="monitoring_updated").order_by(AuditLog.id).all():
        match = _AUDIT_DETAIL.fullmatch(entry.detail or "")
        if not match or int(match.group(1)) not in wanted:
            continue
        target_id = int(match.group(1))
        if match.group(2) == "off":
            found.pop(target_id, None)
        else:
            found[target_id] = (entry.user_id, entry.timestamp)
    return found


def monitored_entries(user) -> list:
    """Every target with continuous monitoring on that `user` may see, with who set it up: an analyst
    sees their own, the roles that work across the organisation (admin, threat intelligence) see all.

    Each entry: target, owner_name, set_by_name, set_by_role, set_by_you, set_at, interval_label,
    last_scan, next_scan and state ("scanning", "due" or "scheduled"). Monitoring that was set up
    before the setter was recorded is attributed from the audit log, else to the target's owner."""
    query = AuthorizedTarget.query.filter(
        AuthorizedTarget.monitor_interval_days.isnot(None), AuthorizedTarget.authorized.is_(True)
    ).order_by(AuthorizedTarget.domain)
    if user.role not in (ROLE_IT_ADMIN, ROLE_THREAT_INTEL):
        query = query.filter(AuthorizedTarget.owner_id == user.id)
    targets = query.all()
    if not targets:
        return []

    earlier = _earlier_setters([t.id for t in targets if t.monitor_set_by is None])
    setter = {t.id: (t.monitor_set_by, t.monitor_set_at) if t.monitor_set_by else earlier.get(t.id, (t.owner_id, None)) for t in targets}
    wanted = {t.owner_id for t in targets} | {who for who, _ in setter.values() if who}
    people = {u.id: u for u in User.query.filter(User.id.in_(wanted)).all()}

    entries = []
    for target in targets:
        set_by_id, set_at = setter[target.id]
        who, owner = people.get(set_by_id), people.get(target.owner_id)
        entries.append({
            "target": target,
            "owner_name": display_name(owner) if owner else "a former user",
            "set_by_name": display_name(who) if who else "a former user",
            "set_by_role": who.role if who else None,
            "set_by_you": set_by_id == user.id,
            "set_at": set_at,
            "interval_label": interval_label(target.monitor_interval_days),
            "last_scan": last_activity(target),
            "next_scan": next_run_at(target),
            "state": "scanning" if target_is_scanning(target.id) else ("due" if is_due(target) else "scheduled"),
        })
    return entries


def mark_seen(user, now: Optional[datetime] = None) -> bool:
    """Remember that `user` is here now (at most once a minute). A later sign-in compares against it."""
    now = now or utcnow()
    if user.last_seen_at and (now - user.last_seen_at).total_seconds() < SEEN_THROTTLE_SECONDS:
        return False
    user.last_seen_at = now
    db.session.commit()
    return True


def away_summary(target_ids, since: Optional[datetime]) -> Optional[dict]:
    """What monitoring did for these targets since `since` (when the user was last here), or None
    when there is nothing to tell: monitoring only deserves a mention if it did something."""
    if since is None or not target_ids:
        return None
    runs = MonitorRun.query.filter(
        MonitorRun.target_id.in_(target_ids), MonitorRun.trigger == "scheduled", MonitorRun.started_at >= since
    ).all()
    changes = MonitorEvent.query.filter(MonitorEvent.target_id.in_(target_ids), MonitorEvent.created_at >= since).count()
    if not runs and not changes:
        return None
    return {
        "since": since,
        "runs": len(runs),
        "failed": sum(1 for r in runs if r.status in ("failed", "interrupted")),
        "changes": changes,
    }


# ------------------------------------------------------------------------ events
def record_event(target_id: int, event_type: str, subject: str, severity: str = None, detail: str = None) -> MonitorEvent:
    event = MonitorEvent(target_id=target_id, event_type=event_type, subject=subject[:255], severity=severity, detail=detail)
    db.session.add(event)
    db.session.commit()
    return event


def recent_events(target_ids, limit: int = 100) -> list:
    if not target_ids:
        return []
    return (
        MonitorEvent.query.filter(MonitorEvent.target_id.in_(target_ids))
        .order_by(MonitorEvent.created_at.desc(), MonitorEvent.id.desc())
        .limit(limit)
        .all()
    )


def is_first_discovery(target_id: int, scan_id: int) -> bool:
    """True if no discovery had completed before this one, so it only sets the baseline."""
    return (
        Scan.query.filter(
            Scan.target_id == target_id, Scan.scan_type == "asset_discovery", Scan.status == "completed", Scan.id < scan_id
        ).first()
        is None
    )


def is_first_chain(target_id: int, scan_id: int) -> bool:
    """True while the chain this scan belongs to is the target's first (a baseline)."""
    lead = (
        Scan.query.filter(Scan.target_id == target_id, Scan.scan_type == "asset_discovery", Scan.id <= scan_id)
        .order_by(Scan.id.desc())
        .first()
    )
    return lead is None or is_first_discovery(target_id, lead.id)


# ------------------------------------------------------------------------ assets
def sync_discovered_assets(target: AuthorizedTarget, discovered: list, trustworthy: bool, baseline: bool) -> list:
    """Reconcile a discovery result with the assets already known for the target.

    New hosts are added (once each: re-scans no longer duplicate assets); known hosts are marked
    seen. If `trustworthy` (a real run that found something), a host not returned for
    MISSES_BEFORE_MISSING runs in a row is marked missing. Returns the newly created assets."""
    now = utcnow()
    known = {a.subdomain.lower(): a for a in Asset.query.filter_by(target_id=target.id).all() if a.subdomain}
    seen, created = set(), []

    for item in discovered:
        host = (item.get("subdomain") or "").strip()
        key = host.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        asset = known.get(key)
        if asset is None:
            asset = Asset(target_id=target.id, subdomain=host, url=item.get("url"), last_seen_at=now, status="active", missed_runs=0)
            db.session.add(asset)
            created.append(asset)
            if not baseline:
                record_event(target.id, "asset_new", host, detail="Found by subdomain discovery.")
            continue
        asset.url = asset.url or item.get("url")
        asset.last_seen_at = now
        asset.missed_runs = 0
        if asset.status == "missing":
            asset.status = "active"
            if not baseline:
                record_event(target.id, "asset_back", host, detail="Returned by discovery again after being missing.")

    if trustworthy and seen:
        for key, asset in known.items():
            if key in seen or key == target.domain.lower():
                continue
            asset.missed_runs = (asset.missed_runs or 0) + 1
            if asset.missed_runs >= MISSES_BEFORE_MISSING and asset.status != "missing":
                asset.status = "missing"
                record_event(
                    target.id, "asset_missing", asset.subdomain,
                    detail=f"Not returned by the last {MISSES_BEFORE_MISSING} discovery runs. It may have been "
                           "decommissioned, or the subdomain sources simply did not list it.",
                )
    db.session.commit()
    return created


# ---------------------------------------------------------------------- findings
def record_new_findings(target: AuthorizedTarget, created: list, baseline: bool):
    if baseline:
        return
    for vuln in created:
        record_event(target.id, "finding_new", vuln.title, severity=vuln.severity, detail=_where(vuln))


def _where(vuln: Vulnerability) -> str:
    asset = db.session.get(Asset, vuln.asset_id)
    return f"On {asset.subdomain or asset.url or asset.ip_address}." if asset else ""


def store_new_findings(target: AuthorizedTarget, asset: Asset, findings: list, baseline: bool) -> list:
    """Store findings not already recorded on the asset (by title) and report them as new."""
    created = vulnerability_service.store_new_findings(asset.id, findings)
    record_new_findings(target, created, baseline)
    return created


def reconcile_findings(target: AuthorizedTarget, asset: Asset, prefix: str, current: list, baseline: bool) -> Reconciled:
    """Compare a deterministic check's results with what is on record for the asset.

    Only for checks whose absence really means "fixed" (the [Dork] exposure checks and the [Config]
    checks). A recorded finding that is no longer detected is marked resolved; one the analyst
    resolved that is detected again is reopened; anything else is new. A finding the analyst marked
    false positive is left alone."""
    existing = Vulnerability.query.filter(Vulnerability.asset_id == asset.id, Vulnerability.title.like(f"{prefix}%")).all()
    by_title = {v.title: v for v in existing}
    now_found = {}
    for item in current:
        now_found.setdefault(item["title"], item)

    reopened = [by_title[t] for t in now_found if t in by_title and by_title[t].status == "resolved"]
    resolved = [v for v in existing if v.title not in now_found and v.status in LIVE_STATUSES]
    for vuln in reopened:
        vuln.status = "open"
    for vuln in resolved:
        vuln.status = "resolved"
    db.session.commit()

    created = vulnerability_service.store_new_findings(asset.id, [item for t, item in now_found.items() if t not in by_title])
    record_new_findings(target, created, baseline)
    for vuln in reopened:
        record_event(target.id, "finding_reopened", vuln.title, severity=vuln.severity, detail=f"Detected again. {_where(vuln)}".strip())
    for vuln in resolved:
        record_event(target.id, "finding_resolved", vuln.title, severity=vuln.severity,
                     detail=f"No longer detected by the latest scan, so it was marked resolved. {_where(vuln)}".strip())
    return Reconciled(created, resolved, reopened)


# ------------------------------------------------------------------------ alerts
def notable(events: list) -> list:
    """The events worth an email: asset changes, new or reopened findings that are critical or high."""
    return [
        e for e in events
        if e.event_type in ("asset_new", "asset_missing")
        or (e.event_type in ("finding_new", "finding_reopened") and e.severity in ALERT_SEVERITIES)
    ]


def send_digest(app, target_id: int, since: datetime) -> bool:
    """Email the target's owner about what the scan that started at `since` changed.
    Only for monitored targets, and only when something notable happened."""
    from utils.mailer import send_email

    target = db.session.get(AuthorizedTarget, target_id)
    if not target or not target.monitor_interval_days or not app.config.get("MONITOR_ALERT_EMAILS"):
        return False
    events = MonitorEvent.query.filter(MonitorEvent.target_id == target_id, MonitorEvent.created_at >= since).order_by(MonitorEvent.id).all()
    important = notable(events)
    owner = db.session.get(User, target.owner_id)
    if not important or not owner or not owner.email:
        return False

    lines = [f"Continuous monitoring found {len(important)} notable change(s) on {target.domain}:", ""]
    for event in important[:15]:
        label = EVENT_LABELS.get(event.event_type, event.event_type)
        lines.append(f"- {label}: {event.subject}" + (f" [{event.severity}]" if event.severity else ""))
    if len(important) > 15:
        lines.append(f"...and {len(important) - 15} more.")
    lines += ["", "Open the dashboard for details: Changes detected."]
    sent = send_email(owner.email, f"[ASM] {len(important)} change(s) detected on {target.domain}", "\n".join(lines))
    log_action(owner.id, "monitor_alert_sent" if sent else "monitor_alert_not_sent", detail=f"target_id={target.id} events={len(important)}")
    return sent
