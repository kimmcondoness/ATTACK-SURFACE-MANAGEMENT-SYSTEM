import os

from flask import Blueprint, current_app, flash, redirect, request, send_file, url_for
from flask_login import current_user, login_required

from models import REPORT_TYPES, ROLE_ANALYST, ROLE_IT_ADMIN, AuthorizedTarget, Report
from services import report_service, report_share_service
from utils.audit import log_action

workspace_reports_bp = Blueprint("workspace_reports", __name__, url_prefix="/workspace/reports")

_REPORT_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST)


def _owned_target(target_id):
    target = AuthorizedTarget.query.get(target_id)
    if not target:
        return None
    if target.owner_id != current_user.id and current_user.role != ROLE_IT_ADMIN:
        return None
    return target


@workspace_reports_bp.route("/generate", methods=["POST"])
@login_required
def generate_report():
    if current_user.role not in _REPORT_ROLES:
        flash("You do not have permission to generate reports.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    target_id = request.form.get("target_id", type=int)
    report_type = request.form.get("report_type", "")
    redirect_url = url_for("findings.findings_page", target_id=target_id)

    target = _owned_target(target_id)
    if not target:
        flash("Choose a target before generating a report.", "error")
        return redirect(redirect_url)

    if report_type not in REPORT_TYPES:
        flash("Invalid report type.", "error")
        return redirect(redirect_url)

    reports_dir = current_app.config["REPORTS_DIR"]
    if report_type == "pdf":
        report = report_service.generate_pdf_report(target, reports_dir, current_user.id)
    else:
        report = report_service.generate_csv_report(target, reports_dir, current_user.id)

    log_action(current_user.id, "report_generated", detail=f"target_id={target.id} type={report_type}")
    return send_file(report.file_path, as_attachment=True)


@workspace_reports_bp.route("/<int:report_id>/share", methods=["POST"])
@login_required
def share_report(report_id):
    """Share a report you generated with Threat Intelligence, who then download the very same file."""
    report = Report.query.get(report_id)
    back = url_for("findings.findings_page", target_id=request.form.get("target_id", type=int))
    if current_user.role not in _REPORT_ROLES or not report or not _owned_target(report.target_id):
        flash("Report not found.", "error")
        return redirect(back)

    if not os.path.exists(report.file_path):
        flash("That report file is no longer available, so there is nothing to share. Generate a new one.", "error")
        return redirect(back)

    _share, created = report_share_service.share_report(report, current_user.id, request.form.get("note"))
    flash(
        "Shared with Threat Intelligence. They can now download this report." if created
        else "This report is already shared with Threat Intelligence.",
        "success",
    )
    return redirect(back)


@workspace_reports_bp.route("/<int:report_id>/unshare", methods=["POST"])
@login_required
def unshare_report(report_id):
    """Take a report back out of the Threat Intelligence inbox."""
    report = Report.query.get(report_id)
    back = url_for("findings.findings_page", target_id=request.form.get("target_id", type=int))
    if current_user.role not in _REPORT_ROLES or not report or not _owned_target(report.target_id):
        flash("Report not found.", "error")
        return redirect(back)

    if report_share_service.withdraw_share(report.id, current_user.id):
        flash("Withdrawn. Threat Intelligence can no longer see this report.", "success")
    else:
        flash("That report was not shared.", "error")
    return redirect(back)


@workspace_reports_bp.route("/<int:report_id>/download", methods=["GET"])
@login_required
def download_report(report_id):
    report = Report.query.get(report_id)
    if current_user.role not in _REPORT_ROLES or not report or not _owned_target(report.target_id):
        flash("Report not found.", "error")
        return redirect(url_for("findings.findings_page"))

    if not os.path.exists(report.file_path):
        flash("That report file is no longer available. Generate a new one.", "error")
        return redirect(url_for("findings.findings_page", target_id=report.target_id))

    log_action(current_user.id, "report_downloaded", detail=f"report_id={report_id}")
    return send_file(report.file_path, as_attachment=True)
