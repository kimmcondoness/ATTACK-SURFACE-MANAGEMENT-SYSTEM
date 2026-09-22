import os

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user, login_required

from models import REPORT_TYPES, ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_SECURITY_TEAM, Report
from services import report_service, target_service
from utils.audit import log_action
from utils.decorators import role_required

reports_bp = Blueprint("reports", __name__, url_prefix="/api")

_ALL_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_SECURITY_TEAM)


@reports_bp.route("/targets/<int:target_id>/reports", methods=["POST"])
@login_required
@role_required(*_ALL_ROLES)
def generate_report(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404

    payload = request.get_json(silent=True) or {}
    report_type = payload.get("report_type", "pdf")
    if report_type not in REPORT_TYPES:
        return jsonify({"error": f"Invalid report_type. Allowed: {', '.join(REPORT_TYPES)}"}), 400

    reports_dir = current_app.config["REPORTS_DIR"]
    if report_type == "pdf":
        report = report_service.generate_pdf_report(target, reports_dir, current_user.id)
    else:
        report = report_service.generate_csv_report(target, reports_dir, current_user.id)

    log_action(current_user.id, "report_generated", detail=f"target_id={target_id} type={report_type}")
    return jsonify({"report": report.to_dict()}), 201


@reports_bp.route("/targets/<int:target_id>/reports", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def list_reports(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404
    reports = report_service.list_reports_for_target(target_id)
    return jsonify({"reports": [r.to_dict() for r in reports]})


@reports_bp.route("/reports/<int:report_id>/download", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def download_report(report_id):
    report = Report.query.get(report_id)
    if not report or not os.path.exists(report.file_path):
        return jsonify({"error": "Report not found."}), 404
    return send_file(report.file_path, as_attachment=True)
