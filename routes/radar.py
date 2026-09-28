from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from models import ROLE_ANALYST
from services import radar_service
from utils.decorators import role_required

radar_bp = Blueprint("radar", __name__, url_prefix="/workspace/radar")


@radar_bp.route("", methods=["GET"])
@login_required
@role_required(ROLE_ANALYST)
def radar_data():
    """JSON snapshot the dashboard radar polls while a scan is running."""
    snapshot = radar_service.radar_snapshot(current_user.id, request.args.get("target_id", type=int))
    return jsonify(snapshot)
