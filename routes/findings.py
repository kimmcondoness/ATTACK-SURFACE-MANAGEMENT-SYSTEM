from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from models import SEVERITIES, VULN_STATUSES, Report
from services import inventory_service
from services.risk_service import vulnerability_priority
from services.report_service import opened_report_ids
from services.dork_service import total_dork_count
from services.vulnerability_service import delete_findings, findings_for_targets
from utils.audit import log_action
from utils.workspace import redirect_non_analyst

findings_bp = Blueprint("findings", __name__, url_prefix="/workspace/findings")


def _asset_label(asset):
    return asset.subdomain or asset.url or asset.ip_address or f"asset-{asset.id}"


@findings_bp.route("", methods=["GET"])
@login_required
def findings_page():
    other_role = redirect_non_analyst()
    if other_role:
        return other_role

    targets = inventory_service.owned_targets(current_user.id)
    owned_ids = {t.id for t in targets}
    requested = request.args.get("target_id", type=int)
    selected_target_id = requested if requested in owned_ids else None
    scoped_ids = [selected_target_id] if selected_target_id else list(owned_ids)

    findings = findings_for_targets(scoped_ids)
    reports = (
        Report.query.filter(Report.target_id.in_(scoped_ids)).order_by(Report.generated_at.desc()).all()
        if scoped_ids
        else []
    )
    severity_totals = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}

    return render_template(
        "findings.html",
        active_nav="findings",
        user=current_user,
        findings=findings,
        reports=reports,
        read_report_ids=opened_report_ids(current_user.id),
        target_map={t.id: t.domain for t in targets},
        asset_label=_asset_label,
        priority=vulnerability_priority,
        severity_totals=severity_totals,
        status_choices=VULN_STATUSES,
        targets=targets,
        selected_target_id=selected_target_id,
        selected_domain=next((t.domain for t in targets if t.id == selected_target_id), None),
        nav_counts=inventory_service.nav_counts(targets),
        dork_count=total_dork_count(),
    )


@findings_bp.route("/delete", methods=["POST"])
@login_required
def delete_selected():
    other_role = redirect_non_analyst()
    if other_role:
        return other_role

    back = url_for("findings.findings_page", target_id=request.form.get("target_id", type=int))
    vuln_ids = request.form.getlist("vuln_ids", type=int)
    if not vuln_ids:
        flash("Select at least one finding to delete.", "error")
        return redirect(back)

    deleted = delete_findings(vuln_ids, current_user.id)
    log_action(current_user.id, "findings_deleted", detail=f"count={deleted} ids={','.join(map(str, vuln_ids))}")
    flash(f"Deleted {deleted} finding{'' if deleted == 1 else 's'}.", "success")
    return redirect(back)
