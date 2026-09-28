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
"""

import logging
import os
import threading
from collections import namedtuple
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import or_

from extensions import db
from models import (
    MONITOR_INTERVALS,
    Asset,
    AuthorizedTarget,
    MonitorEvent,
    Scan,
    User,
    Vulnerability,
)
from services import job_registry, vulnerability_service
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
    target.monitor_interval_days = MONITOR_INTERVALS[choice]
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
        from services.scan_runner import start_chain as starter

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


def _scheduler_loop(app):
    poll = app.config.get("MONITOR_POLL_SECONDS", 60)
    while not _scheduler_stop.wait(poll):
        try:
            with app.app_context():
                run_due(app)
        except Exception:   # noqa: BLE001 - one bad tick must never end monitoring
            app.logger.exception("Monitoring scheduler tick failed")


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
        _scheduler_stop.clear()
        _scheduler_thread = threading.Thread(target=_scheduler_loop, args=(app,), daemon=True, name="monitor-scheduler")
        _scheduler_thread.start()
        app.logger.info("Continuous monitoring scheduler started (checks every %ss).", app.config.get("MONITOR_POLL_SECONDS", 60))
        return _scheduler_thread


def stop_scheduler():
    _scheduler_stop.set()


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
