from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models import ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_SECURITY_TEAM
from services import asset_service, scan_service, target_service
from services.scan_service import UnauthorizedTargetError
from utils.audit import log_action
from utils.decorators import role_required

scans_bp = Blueprint("scans", __name__, url_prefix="/api")

_SCAN_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST)
_ALL_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_SECURITY_TEAM)


@scans_bp.route("/targets/<int:target_id>/scans/discovery", methods=["POST"])
@login_required
@role_required(*_SCAN_ROLES)
def start_asset_discovery(target_id):
    target = target_service.get_target(target_id)
    try:
        scan = scan_service.run_asset_discovery(target, current_user.id)
    except UnauthorizedTargetError as exc:
        return jsonify({"error": str(exc)}), 403

    log_action(current_user.id, "scan_asset_discovery", detail=f"target_id={target_id} scan_id={scan.id}")
    return jsonify({"scan": scan.to_dict()}), 201


@scans_bp.route("/assets/<int:asset_id>/scans/ports", methods=["POST"])
@login_required
@role_required(*_SCAN_ROLES)
def start_port_discovery(asset_id):
    asset = asset_service.get_asset(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found."}), 404
    target = target_service.get_target(asset.target_id)

    try:
        scan = scan_service.run_port_discovery(target, asset, current_user.id)
    except UnauthorizedTargetError as exc:
        return jsonify({"error": str(exc)}), 403

    log_action(current_user.id, "scan_port_discovery", detail=f"asset_id={asset_id} scan_id={scan.id}")
    return jsonify({"scan": scan.to_dict()}), 201


@scans_bp.route("/assets/<int:asset_id>/scans/vulnerabilities", methods=["POST"])
@login_required
@role_required(*_SCAN_ROLES)
def start_vulnerability_scan(asset_id):
    asset = asset_service.get_asset(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found."}), 404
    target = target_service.get_target(asset.target_id)

    try:
        scan = scan_service.run_vulnerability_scan(target, asset, current_user.id)
    except UnauthorizedTargetError as exc:
        return jsonify({"error": str(exc)}), 403

    log_action(current_user.id, "scan_vulnerability", detail=f"asset_id={asset_id} scan_id={scan.id}")
    return jsonify({"scan": scan.to_dict()}), 201


@scans_bp.route("/targets/<int:target_id>/scans", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def list_scans(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404
    scans = scan_service.list_scans_for_target(target_id)
    return jsonify({"scans": [s.to_dict() for s in scans]})
