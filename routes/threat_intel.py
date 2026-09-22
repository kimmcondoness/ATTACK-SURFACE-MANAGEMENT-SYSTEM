from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import ROLE_IT_ADMIN, ROLE_THREAT_INTEL, Asset, AuthorizedTarget, Vulnerability
from services.kev_service import recent_kev_entries
from services.risk_service import vulnerability_priority
from utils.audit import log_action

threat_intel_bp = Blueprint("threat_intel", __name__, url_prefix="/workspace/threat-intel")

_ALLOWED_ROLES = (ROLE_THREAT_INTEL, ROLE_IT_ADMIN)
_STATUS_CHOICES = ("open", "in_progress", "resolved", "false_positive")


def _forbidden():
    flash("You do not have permission to view Threat Intelligence.", "error")
    return redirect(url_for("auth_pages.dashboard_placeholder"))


@threat_intel_bp.route("", methods=["GET"])
@login_required
def threat_intel_page():
    if current_user.role not in _ALLOWED_ROLES:
        return _forbidden()

    # Threat Intelligence is an org-wide function -- it reviews risk across
    # every authorized target, not just ones this specific analyst created,
    # unlike the Cybersecurity Analyst's own-targets-only Dashboard.
    targets = AuthorizedTarget.query.order_by(AuthorizedTarget.created_at.desc()).all()
    target_ids = [t.id for t in targets]
    target_map = {t.id: t.domain for t in targets}
    asset_target_map = {
        a.id: a.target_id
        for a in Asset.query.filter(Asset.target_id.in_(target_ids)).all()
    } if target_ids else {}

    all_vulns = (
        Vulnerability.query.join(Asset).filter(Asset.target_id.in_(target_ids)).all()
        if target_ids
        else []
    )
    live_vulns = [v for v in all_vulns if v.status in ("open", "in_progress")]

    prioritized = sorted(live_vulns, key=vulnerability_priority, reverse=True)
    kev_matches = [v for v in prioritized if v.kev]

    stat_values = {
        "findings": len(live_vulns),
        "kev": len(kev_matches),
        "exploitable": sum(1 for v in live_vulns if v.exploit_available),
        "avg_cvss": (
            round(sum(v.cvss_score for v in live_vulns if v.cvss_score is not None) / max(
                sum(1 for v in live_vulns if v.cvss_score is not None), 1
            ), 1)
            if any(v.cvss_score is not None for v in live_vulns)
            else 0
        ),
    }
    max_stat = max(stat_values["findings"], stat_values["kev"], stat_values["exploitable"], stat_values["avg_cvss"]) or 0
    stat_bar_pct = {
        key: (round(value * 100 / max_stat) if max_stat else 0) for key, value in stat_values.items()
    }

    kev_feed = recent_kev_entries(10)

    return render_template(
        "threat_intel.html",
        active_nav="threat_intel",
        user=current_user,
        targets=targets,
        target_map=target_map,
        asset_target_map=asset_target_map,
        prioritized=prioritized[:100],
        prioritized_total=len(prioritized),
        kev_matches=kev_matches,
        kev_feed=kev_feed,
        stat_values=stat_values,
        stat_bar_pct=stat_bar_pct,
        status_choices=_STATUS_CHOICES,
        priority=vulnerability_priority,
    )


@threat_intel_bp.route("/<int:vuln_id>/status", methods=["POST"])
@login_required
def update_status(vuln_id):
    if current_user.role not in _ALLOWED_ROLES:
        return _forbidden()

    vuln = Vulnerability.query.get(vuln_id)
    if not vuln:
        flash("Finding not found.", "error")
        return redirect(url_for("threat_intel.threat_intel_page"))

    status = request.form.get("status", "")
    if status not in _STATUS_CHOICES:
        flash("Invalid status.", "error")
        return redirect(url_for("threat_intel.threat_intel_page"))

    vuln.status = status
    db.session.commit()
    log_action(current_user.id, "threat_intel_status_updated", detail=f"vuln_id={vuln_id} status={status}")
    return redirect(url_for("threat_intel.threat_intel_page"))
