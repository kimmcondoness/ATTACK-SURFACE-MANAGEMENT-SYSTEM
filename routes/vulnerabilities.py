from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models import ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_THREAT_INTEL, SEVERITIES, VULN_STATUSES, Vulnerability
from services import vulnerability_service
from utils.audit import log_action
from utils.decorators import role_required

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")

_ALL_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_THREAT_INTEL)


@vulnerabilities_bp.route("", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def list_vulnerabilities():
    target_id = request.args.get("target_id", type=int)
    severity = request.args.get("severity")
    if severity and severity not in SEVERITIES:
        return jsonify({"error": f"Invalid severity filter. Allowed: {', '.join(SEVERITIES)}"}), 400

    vulns = vulnerability_service.list_vulnerabilities(target_id=target_id, severity=severity)
    return jsonify({"vulnerabilities": [v.to_dict() for v in vulns]})


@vulnerabilities_bp.route("/<int:vulnerability_id>/status", methods=["PUT"])
@login_required
@role_required(ROLE_IT_ADMIN, ROLE_ANALYST)
def update_status(vulnerability_id):
    vuln = Vulnerability.query.get(vulnerability_id)
    if not vuln:
        return jsonify({"error": "Vulnerability not found."}), 404

    payload = request.get_json(silent=True) or {}
    status = payload.get("status", "")
    if status not in VULN_STATUSES:
        return jsonify({"error": "Invalid status."}), 400

    vuln = vulnerability_service.update_vulnerability_status(vuln, status)
    log_action(current_user.id, "vulnerability_status_updated", detail=f"vuln_id={vulnerability_id} status={status}")
    return jsonify({"vulnerability": vuln.to_dict()})
