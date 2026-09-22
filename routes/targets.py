from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models import ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_SECURITY_TEAM
from services import target_service
from utils.audit import log_action
from utils.decorators import role_required
from utils.validators import ValidationError

targets_bp = Blueprint("targets", __name__, url_prefix="/api/targets")

_ALL_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_SECURITY_TEAM)


@targets_bp.route("", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def list_targets():
    targets = target_service.list_targets()
    return jsonify({"targets": [t.to_dict() for t in targets]})


@targets_bp.route("", methods=["POST"])
@login_required
@role_required(ROLE_IT_ADMIN, ROLE_ANALYST)
def create_target():
    payload = request.get_json(silent=True) or {}
    try:
        target = target_service.create_target(
            owner_id=current_user.id,
            domain=payload.get("domain", ""),
            description=payload.get("description", ""),
            authorized=payload.get("authorized", False),
        )
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    log_action(current_user.id, "target_created", detail=f"target_id={target.id} domain={target.domain}")
    return jsonify({"target": target.to_dict()}), 201


@targets_bp.route("/<int:target_id>", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def get_target(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404
    return jsonify({"target": target.to_dict()})


@targets_bp.route("/<int:target_id>", methods=["PUT"])
@login_required
@role_required(ROLE_IT_ADMIN, ROLE_ANALYST)
def update_target(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404

    payload = request.get_json(silent=True) or {}
    try:
        target = target_service.update_target(target, **payload)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    log_action(current_user.id, "target_updated", detail=f"target_id={target.id}")
    return jsonify({"target": target.to_dict()})


@targets_bp.route("/<int:target_id>", methods=["DELETE"])
@login_required
@role_required(ROLE_IT_ADMIN)
def delete_target(target_id):
    target = target_service.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404
    target_service.delete_target(target)
    log_action(current_user.id, "target_deleted", detail=f"target_id={target_id}")
    return jsonify({"message": "Target deleted."})
