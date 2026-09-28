from flask import Blueprint, jsonify
from flask_login import login_required

from models import ROLE_ANALYST, ROLE_IT_ADMIN, ROLE_THREAT_INTEL
from services.risk_service import dashboard_summary
from utils.decorators import role_required

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

_ALL_ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_THREAT_INTEL)


@dashboard_bp.route("", methods=["GET"])
@login_required
@role_required(*_ALL_ROLES)
def get_dashboard():
    return jsonify(dashboard_summary())
