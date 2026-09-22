from flask import Blueprint, render_template

legal_bp = Blueprint("legal", __name__)


@legal_bp.route("/privacy-policy", methods=["GET"])
def privacy_policy():
    return render_template("privacy_policy.html")


@legal_bp.route("/terms-of-service", methods=["GET"])
def terms_of_service():
    return render_template("terms_of_service.html")
