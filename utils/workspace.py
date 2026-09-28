from flask import redirect, url_for
from flask_login import current_user

from models import ROLE_IT_ADMIN, ROLE_THREAT_INTEL


def redirect_non_analyst():
    """Admins and Threat Intel have their own home pages, so the analyst
    workspace pages send them there instead of rendering an empty view."""
    if current_user.role == ROLE_IT_ADMIN:
        return redirect(url_for("auth_pages.admin_dashboard"))
    if current_user.role == ROLE_THREAT_INTEL:
        return redirect(url_for("threat_intel.threat_intel_page"))
    return None
