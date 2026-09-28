import csv
import io

from flask import Blueprint, Response, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from models import ROLE_IT_ADMIN, ROLE_THREAT_INTEL, Asset, AuthorizedTarget, Vulnerability
from services import epss_service
from services.kev_service import recent_kev_entries
from services.risk_service import vulnerability_priority
from utils.audit import log_action

threat_intel_bp = Blueprint("threat_intel", __name__, url_prefix="/workspace/threat-intel")

_ALLOWED_ROLES = (ROLE_THREAT_INTEL, ROLE_IT_ADMIN)


def _forbidden():
    flash("You do not have permission to view Threat Intelligence.", "error")
    return redirect(url_for("auth_pages.dashboard_placeholder"))


def _live_findings():
    # Org-wide on purpose: unlike the analyst's own-targets workspace, intel
    # reviews risk across every authorized target.
    targets = AuthorizedTarget.query.order_by(AuthorizedTarget.created_at.desc()).all()
    target_ids = [t.id for t in targets]
    if not target_ids:
        return targets, {}, []

    asset_target_map = {
        a.id: a.target_id for a in Asset.query.filter(Asset.target_id.in_(target_ids)).all()
    }
    vulns = Vulnerability.query.join(Asset).filter(Asset.target_id.in_(target_ids)).all()
    live = [v for v in vulns if v.status in ("open", "in_progress")]
    return targets, asset_target_map, sorted(live, key=vulnerability_priority, reverse=True)


@threat_intel_bp.route("", methods=["GET"])
@login_required
def threat_intel_page():
    if current_user.role not in _ALLOWED_ROLES:
        return _forbidden()

    targets, asset_target_map, prioritized = _live_findings()
    target_map = {t.id: t.domain for t in targets}
    kev_matches = [v for v in prioritized if v.kev]
    scored = [v.cvss_score for v in prioritized if v.cvss_score is not None]

    stat_values = {
        "findings": len(prioritized),
        "kev": len(kev_matches),
        "exploitable": sum(1 for v in prioritized if v.exploit_available),
        "avg_cvss": round(sum(scored) / len(scored), 1) if scored else 0,
    }
    max_stat = max(stat_values["findings"], stat_values["kev"], stat_values["exploitable"], stat_values["avg_cvss"]) or 0
    stat_bar_pct = {
        key: (round(value * 100 / max_stat) if max_stat else 0) for key, value in stat_values.items()
    }

    kev_feed = recent_kev_entries(10)

    shown = prioritized[:100]
    scores = epss_service.lookup([cve for v in shown for cve in epss_service.cve_ids(v.cve)])

    return render_template(
        "threat_intel.html",
        active_nav="threat_intel",
        user=current_user,
        targets=targets,
        target_map=target_map,
        asset_target_map=asset_target_map,
        prioritized=shown,
        prioritized_total=len(prioritized),
        kev_matches=kev_matches,
        kev_feed=kev_feed,
        stat_values=stat_values,
        stat_bar_pct=stat_bar_pct,
        priority=vulnerability_priority,
        cve_list=epss_service.cve_ids,
        epss_for=lambda vuln: epss_service.best_score(vuln.cve, scores),
        epss_level=epss_service.level,
    )


@threat_intel_bp.route("/briefing.csv", methods=["GET"])
@login_required
def briefing_csv():
    if current_user.role not in _ALLOWED_ROLES:
        return _forbidden()

    targets, asset_target_map, prioritized = _live_findings()
    target_map = {t.id: t.domain for t in targets}

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Priority", "CVE", "Severity", "CVSS", "In CISA KEV", "Public exploit", "Target", "Title"])
    for v in prioritized:
        writer.writerow([
            vulnerability_priority(v),
            v.cve or "-",
            v.severity,
            v.cvss_score if v.cvss_score is not None else "-",
            "yes" if v.kev else "no",
            "yes" if v.exploit_available else "no",
            target_map.get(asset_target_map.get(v.asset_id), "unknown"),
            v.title,
        ])

    log_action(current_user.id, "threat_briefing_exported", detail=f"rows={len(prioritized)}")
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat-briefing.csv"},
    )
