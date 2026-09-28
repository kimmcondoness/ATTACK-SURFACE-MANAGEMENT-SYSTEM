from functools import wraps

from flask import flash, jsonify, redirect, url_for
from flask_login import current_user


def role_required(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Authentication required."}), 401
            if current_user.role not in allowed_roles:
                return jsonify({"error": "You do not have permission to perform this action."}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def admin_page_required(fn):
    """For HTML pages only the IT Administrator may open: anyone else is sent
    back to their own home with a message (role_required answers with JSON)."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth_pages.login_page"))
        if current_user.role != "it_admin":
            flash("You do not have permission to view that page.", "error")
            return redirect(url_for("auth_pages.dashboard_placeholder"))
        return fn(*args, **kwargs)

    return wrapper
