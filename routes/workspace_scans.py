import threading

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

from extensions import db
from models import ROLE_ANALYST, ROLE_IT_ADMIN, AuthorizedTarget, Scan
from scanner.base import ScanControl
from services import job_registry, scan_service
from utils.audit import log_action
from utils.validators import ValidationError, extract_domain

workspace_scans_bp = Blueprint("workspace_scans", __name__, url_prefix="/workspace/scan")

_SCAN_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST)


def _own_scan_or_none(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        return None
    target = AuthorizedTarget.query.get(scan.target_id)
    if not target or (target.owner_id != current_user.id and current_user.role != ROLE_IT_ADMIN):
        return None
    return scan


def _run_chain_in_background(app, target_id, user_id, control, lead_scan_id):
    with app.app_context():
        target = AuthorizedTarget.query.get(target_id)
        lead_scan = Scan.query.get(lead_scan_id)
        try:
            scan_service.run_scan_chain(target, user_id, control, lead_scan=lead_scan)
        except Exception as exc:  # noqa: BLE001 - surface any scanner crash instead of losing the thread silently
            lead_scan = Scan.query.get(lead_scan_id)
            if lead_scan and lead_scan.status not in ("completed", "failed", "stopped"):
                lead_scan.status = "failed"
                lead_scan.result_summary = f"Scan crashed: {exc}"
                db.session.commit()
        finally:
            job_registry.unregister(lead_scan_id)


@workspace_scans_bp.route("/start", methods=["POST"])
@login_required
def start_scan():
    if current_user.role not in _SCAN_ROLES:
        return jsonify({"error": "You do not have permission to run scans."}), 403

    payload = request.get_json(silent=True) or {}
    raw_input = payload.get("domain_or_url", "")

    try:
        domain = extract_domain(raw_input)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    target = AuthorizedTarget.query.filter_by(owner_id=current_user.id, domain=domain).first()
    if not target:
        target = AuthorizedTarget(domain=domain, owner_id=current_user.id, authorized=True)
        db.session.add(target)
        db.session.commit()
    elif not target.authorized:
        target.authorized = True
        db.session.commit()

    lead_scan = Scan(target_id=target.id, scan_type="asset_discovery", status="pending", started_by=current_user.id)
    db.session.add(lead_scan)
    db.session.commit()

    control = ScanControl()
    thread = threading.Thread(
        target=_run_chain_in_background,
        args=(current_app._get_current_object(), target.id, current_user.id, control, lead_scan.id),
        daemon=True,
    )
    job_registry.register(lead_scan.id, thread, control)
    thread.start()

    log_action(current_user.id, "scan_chain_started", detail=f"target_id={target.id} scan_id={lead_scan.id} domain={domain}")
    return jsonify({"scan_id": lead_scan.id, "target_id": target.id, "domain": domain}), 201


@workspace_scans_bp.route("/<int:scan_id>/pause", methods=["POST"])
@login_required
def pause_scan(scan_id):
    scan = _own_scan_or_none(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    control = job_registry.get_control(scan_id)
    if not control or not job_registry.is_running(scan_id):
        return jsonify({"error": "Scan is not currently running."}), 409

    control.request_pause()
    log_action(current_user.id, "scan_paused", detail=f"scan_id={scan_id}")
    return jsonify({"scan_id": scan_id, "status": "paused"})


@workspace_scans_bp.route("/<int:scan_id>/resume", methods=["POST"])
@login_required
def resume_scan(scan_id):
    scan = _own_scan_or_none(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    control = job_registry.get_control(scan_id)
    if not control or not job_registry.is_running(scan_id):
        return jsonify({"error": "Scan is not currently running."}), 409

    control.request_resume()
    log_action(current_user.id, "scan_resumed", detail=f"scan_id={scan_id}")
    return jsonify({"scan_id": scan_id, "status": "running"})


@workspace_scans_bp.route("/<int:scan_id>/stop", methods=["POST"])
@login_required
def stop_scan(scan_id):
    scan = _own_scan_or_none(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    control = job_registry.get_control(scan_id)
    if control:
        control.request_stop()
    log_action(current_user.id, "scan_stopped", detail=f"scan_id={scan_id}")
    return jsonify({"scan_id": scan_id, "status": "stopped"})
