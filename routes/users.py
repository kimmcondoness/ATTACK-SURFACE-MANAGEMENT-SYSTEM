from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from extensions import db
from models import ROLE_IT_ADMIN, ROLES, User
from utils.audit import log_action
from utils.decorators import role_required
from utils.validators import ValidationError, validate_password, validate_role

users_bp = Blueprint("users", __name__, url_prefix="/api/users")


@users_bp.route("", methods=["GET"])
@login_required
@role_required(ROLE_IT_ADMIN)
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users]})


@users_bp.route("", methods=["POST"])
@login_required
@role_required(ROLE_IT_ADMIN)
def create_user():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    email = payload.get("email", "").strip()
    password = payload.get("password", "")
    role = payload.get("role", "")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required."}), 400

    try:
        validate_role(role, ROLES)
        validate_password(password)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "A user with that username or email already exists."}), 409

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    log_action(current_user.id, "user_created", detail=f"created user_id={user.id}")
    return jsonify({"user": user.to_dict()}), 201


@users_bp.route("/<int:user_id>", methods=["PUT"])
@login_required
@role_required(ROLE_IT_ADMIN)
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    payload = request.get_json(silent=True) or {}
    if "role" in payload:
        try:
            validate_role(payload["role"], ROLES)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        user.role = payload["role"]
    if "is_active" in payload:
        user.is_active_flag = bool(payload["is_active"])
    if "password" in payload and payload["password"]:
        try:
            validate_password(payload["password"])
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        user.set_password(payload["password"])

    db.session.commit()
    log_action(current_user.id, "user_updated", detail=f"updated user_id={user.id}")
    return jsonify({"user": user.to_dict()})


@users_bp.route("/<int:user_id>", methods=["DELETE"])
@login_required
@role_required(ROLE_IT_ADMIN)
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    if user.id == current_user.id:
        return jsonify({"error": "You cannot delete your own account."}), 400

    db.session.delete(user)
    db.session.commit()
    log_action(current_user.id, "user_deleted", detail=f"deleted user_id={user_id}")
    return jsonify({"message": "User deleted."})
