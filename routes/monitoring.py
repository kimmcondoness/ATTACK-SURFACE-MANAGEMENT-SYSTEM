from flask import Blueprint, current_app, flash, jsonify, redirect, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import ROLE_ANALYST, ROLE_IT_ADMIN, AuthorizedTarget
from services import monitor_service

monitoring_bp = Blueprint("monitoring", __name__, url_prefix="/workspace/monitoring")


@monitoring_bp.route("/status", methods=["GET"])
@login_required
def status():
    """Is continuous monitoring alive, and what has it done lately? The engine's state comes from
    the heartbeat in the database, so it is the same with or without anyone signed in. The dashboard
    polls this to keep its status line live."""
    target_ids = monitor_service.visible_target_ids(current_user)
    return jsonify(
        {
            "engine": monitor_service.public_status(monitor_service.engine_status(current_app)),
            "activity": monitor_service.activity_totals(target_ids),
            "runs": [run.to_dict() for run in monitor_service.recent_runs(target_ids, 20)],
        }
    )


@monitoring_bp.route("/<int:target_id>", methods=["POST"])
@login_required
def update_monitoring(target_id):
    """Turn a target's automatic re-scanning on (daily / weekly / monthly) or off."""
    back = url_for("auth_pages.workspace_dashboard", target_id=request.form.get("target_id", type=int)) + "#targets"
    if current_user.role not in (ROLE_ANALYST, ROLE_IT_ADMIN):
        flash("You do not have permission to change monitoring.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    target = db.session.get(AuthorizedTarget, target_id)
    if not target or (target.owner_id != current_user.id and current_user.role != ROLE_IT_ADMIN):
        flash("Target not found.", "error")
        return redirect(back)

    try:
        days = monitor_service.set_interval(target, request.form.get("interval", ""), current_user.id)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(back)

    if days is None:
        flash(f"Monitoring turned off for {target.domain}.", "success")
    else:
        scheduler_note = "" if current_app.config.get("MONITOR_SCHEDULER_ENABLED", True) else " (the scheduler is disabled on this server)"
        flash(f"{target.domain} will be re-scanned automatically: {monitor_service.interval_label(days).lower()}{scheduler_note}.", "success")
    return redirect(back)
