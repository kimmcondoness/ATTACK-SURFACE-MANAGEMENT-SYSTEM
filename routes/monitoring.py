from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_THREAT_INTEL, AuthorizedTarget
from services import inventory_service, monitor_service
from services.dork_service import total_dork_count

monitoring_bp = Blueprint("monitoring", __name__, url_prefix="/workspace/monitoring")


@monitoring_bp.app_context_processor
def monitoring_navigation():
    """Gives the sidebar a `monitor_nav()` that lists the monitored targets the signed-in user may see.
    It is a function so the work is only done by pages that actually draw that sidebar section."""
    return {"monitor_nav": lambda: monitor_service.monitored_entries(current_user) if current_user.is_authenticated else []}


@monitoring_bp.route("", methods=["GET"])
@login_required
def overview():
    """Every target with continuous monitoring on, and who set each one up. Analysts see their own;
    the IT Administrator and Threat Intelligence see everyone's."""
    entries = monitor_service.monitored_entries(current_user)
    target_ids = monitor_service.visible_target_ids(current_user)
    context = {
        "user": current_user,
        "active_nav": "monitoring",
        "entries": entries,
        "org_wide": current_user.role in (ROLE_IT_ADMIN, ROLE_THREAT_INTEL),
        "monitor_engine": monitor_service.engine_status(current_app, target_ids=target_ids),
        "monitor_now": monitor_service.utcnow(),
    }
    if current_user.role == ROLE_ANALYST:   # the analyst sidebar also shows the inventory counts
        owned = inventory_service.owned_targets(current_user.id)
        context.update(nav_counts=inventory_service.nav_counts(owned), dork_count=total_dork_count())
    return render_template("monitoring.html", **context)


@monitoring_bp.route("/status", methods=["GET"])
@login_required
def status():
    """Is continuous monitoring alive, and what has it done lately? The engine's state comes from
    the heartbeat in the database, so it is the same with or without anyone signed in. The dashboard
    polls this to keep its status line live."""
    target_ids = monitor_service.visible_target_ids(current_user)
    return jsonify(
        {
            "engine": monitor_service.public_status(monitor_service.engine_status(current_app, target_ids=target_ids)),
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
