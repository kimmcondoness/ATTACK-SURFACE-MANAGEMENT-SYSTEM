import os

from flask import Blueprint, current_app, flash, redirect, request, send_file, url_for
from flask_login import current_user, login_required

from models import REPORT_TYPES, ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_SECURITY_TEAM, ROLE_THREAT_INTEL, AuthorizedTarget, Report
from services import report_service
from utils.audit import log_action

workspace_reports_bp = Blueprint("workspace_reports", __name__, url_prefix="/workspace/reports")

_REPORT_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_SECURITY_TEAM, ROLE_THREAT_INTEL)


def _owned_target(target_id):
    target = AuthorizedTarget.query.get(target_id)
    if not target:
        return None
    # Threat Intel Analysts don't create/own targets -- their role is
    # org-wide risk review, so they can report on any authorized target,
    # same as an admin. Other roles are still limited to their own.
    if target.owner_id != current_user.id and current_user.role not in (ROLE_IT_ADMIN, ROLE_THREAT_INTEL):
        return None
    return target


@workspace_reports_bp.route("/generate", methods=["POST"])
@login_required
def generate_report():
    if current_user.role not in _REPORT_ROLES:
        flash("You do not have permission to generate reports.", "error")
        return redirect(url_for("auth_pages.workspace_dashboard"))

    target_id = request.form.get("target_id", type=int)
    report_type = request.form.get("report_type", "")
    redirect_url = url_for("auth_pages.workspace_dashboard", target_id=target_id)

    target = _owned_target(target_id)
    if not target:
        flash("Select a specific target before generating a report.", "error")
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


@workspace_reports_bp.route("/<int:report_id>/download", methods=["GET"])
@login_required
def download_report(report_id):
    report = Report.query.get(report_id)
    if not report or not _owned_target(report.target_id):
        flash("Report not found.", "error")
        return redirect(url_for("auth_pages.workspace_dashboard"))

    if not os.path.exists(report.file_path):
        flash("That report file is no longer available. Generate a new one.", "error")
        return redirect(url_for("auth_pages.workspace_dashboard", target_id=report.target_id))

    log_action(current_user.id, "report_downloaded", detail=f"report_id={report_id}")
    return send_file(report.file_path, as_attachment=True)
