"""Starting a full scan chain on a background thread.

Used by both the Run button (routes/workspace_scans.py) and the monitoring scheduler
(services/monitor_service.py), so a scheduled scan is exactly the same scan a person would start.
"""

import threading

from extensions import db
from models import AuthorizedTarget, Scan
from scanner.base import ScanControl
from services import job_registry, monitor_service, scan_service


def run_chain_in_background(app, target_id, user_id, control, lead_scan_id):
    started_at = monitor_service.utcnow()
    crashed = False
    with app.app_context():
        target = db.session.get(AuthorizedTarget, target_id)
        lead_scan = db.session.get(Scan, lead_scan_id)
        try:
            scan_service.run_scan_chain(target, user_id, control, lead_scan=lead_scan)
        except Exception as exc:  # noqa: BLE001 - surface any scanner crash instead of losing the thread silently
            crashed = True
            lead_scan = db.session.get(Scan, lead_scan_id)
            if lead_scan and lead_scan.status not in ("completed", "failed", "stopped"):
                lead_scan.status = "failed"
                lead_scan.result_summary = f"Scan crashed: {exc}"
                db.session.commit()
        finally:
            job_registry.unregister(lead_scan_id)
            alert_sent = False
            try:
                alert_sent = bool(monitor_service.send_digest(app, target_id, since=started_at))
            except Exception:  # noqa: BLE001 - an alert that cannot be sent must not look like a scan failure
                app.logger.exception("Could not send the monitoring alert for target %s", target_id)
            try:
                status = "failed" if crashed else ("stopped" if control.stop_requested() else None)
                monitor_service.finish_run(lead_scan_id, status=status, alert_sent=alert_sent)
            except Exception:  # noqa: BLE001 - the monitoring log must never break a scan either
                db.session.rollback()
                app.logger.exception("Could not close the monitoring record for scan %s", lead_scan_id)


def start_chain(app, target, user_id, trigger="manual") -> Scan:
    """Create the lead scan, start the chain on a daemon thread and register it so it can be
    paused, resumed and stopped. Returns the lead (asset_discovery) scan.

    `trigger` is "scheduled" when the monitoring scheduler starts it; a chain that counts as
    monitoring is also written to the monitoring log (see monitor_service.start_run)."""
    lead_scan = Scan(target_id=target.id, scan_type="asset_discovery", status="pending", started_by=user_id)
    db.session.add(lead_scan)
    db.session.flush()   # the monitoring record needs the scan's id
    target.monitor_last_run_at = monitor_service.utcnow()   # restarts this target's monitoring timer
    monitor_service.start_run(target, lead_scan, trigger)
    db.session.commit()

    control = ScanControl()
    thread = threading.Thread(
        target=run_chain_in_background,
        args=(app, target.id, user_id, control, lead_scan.id),
        daemon=True,
    )
    job_registry.register(lead_scan.id, thread, control)
    thread.start()
    return lead_scan
