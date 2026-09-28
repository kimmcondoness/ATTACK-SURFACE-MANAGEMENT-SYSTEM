from flask import Blueprint, jsonify
from flask_login import login_required

from models import ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_THREAT_INTEL
from services import asset_service, target_service
from utils.decorators import role_required

assets_bp = Blueprint("assets", __name__, url_prefix="/api")

_ALL_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_THREAT_INTEL)


@assets_bp.route("/targets/<int:target_id>/assets", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def list_assets(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404
    assets = asset_service.list_assets_for_target(target_id)
    return jsonify({"assets": [a.to_dict() for a in assets]})


@assets_bp.route("/assets/<int:asset_id>", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def get_asset(asset_id):
    asset = asset_service.get_asset(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found."}), 404
    ports = [p.to_dict() for p in asset.ports_services]
    vulnerabilities = [v.to_dict() for v in asset.vulnerabilities]
    return jsonify({"asset": asset.to_dict(), "ports_services": ports, "vulnerabilities": vulnerabilities})
