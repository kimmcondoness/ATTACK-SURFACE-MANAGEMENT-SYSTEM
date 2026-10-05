from flask import Blueprint, jsonify, request, session
from flask_login import current_user, login_required, login_user, logout_user

from extensions import limiter
from models import User
from utils.audit import log_action
from utils.validators import normalize_username

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/csrf-token", methods=["GET"])
def csrf_token():
    from flask_wtf.csrf import generate_csrf

    return jsonify({"csrf_token": generate_csrf()})


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    payload = request.get_json(silent=True) or {}
    username = normalize_username(payload.get("username", ""))
    password = payload.get("password", "")

    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active_flag or not user.check_password(password):
        log_action(None, "login_failed", detail=f"username={username}")
        return jsonify({"error": "Invalid credentials."}), 401

    login_user(user)
    session.permanent = True
    log_action(user.id, "login_success")
    return jsonify({"user": user.to_dict()})


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    log_action(user_id, "logout")
    return jsonify({"message": "Logged out."})


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    return jsonify({"user": current_user.to_dict()})
