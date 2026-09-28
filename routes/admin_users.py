from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from models import ROLES, User
from services import user_admin_service as directory
from utils.decorators import admin_page_required
from utils.validators import ValidationError

admin_users_bp = Blueprint("admin_users", __name__, url_prefix="/admin/users")

_TAB_NAMES = "profile,access,targets,authentication,activity"


def _page_url(user_id, tab):
    return url_for("admin_users.user_page", user_id=user_id, tab=tab)


def _render(subject, tab, status=200, **extra):
    context = {
        "user": current_user,
        "subject": subject,
        "tab": tab,
        "tabs": directory.TABS,
        "subject_name": directory.display_name(subject),
        "subject_initials": directory.initials(subject),
        "role_labels": directory.ROLE_LABELS,
        "is_self": subject.id == current_user.id,
        "last_sign_in": directory.last_sign_in(subject.id),
        "edit_open": False,
        "form": {},
    }
    if tab == "profile":
        context["target_count"] = len(directory.targets_summary(subject.id))
    elif tab == "access":
        context["roles"] = ROLES
        context["capabilities"] = directory.ROLE_CAPABILITIES.get(subject.role, ())
    elif tab == "targets":
        context["targets"] = directory.targets_summary(subject.id)
    elif tab == "authentication":
        context["devices_reset_at"] = directory.trusted_devices_reset_at(subject.id)
    elif tab == "activity":
        context["activity"] = directory.activity_for(subject.id)
    context.update(extra)
    return render_template("admin_user.html", **context), status


@admin_users_bp.route("/<int:user_id>")
@login_required
@admin_page_required
def user_home(user_id):
    User.query.get_or_404(user_id)
    return redirect(_page_url(user_id, "profile"))


@admin_users_bp.route(f"/<int:user_id>/<any({_TAB_NAMES}):tab>")
@login_required
@admin_page_required
def user_page(user_id, tab):
    return _render(User.query.get_or_404(user_id), tab)


@admin_users_bp.route("/<int:user_id>/profile", methods=["POST"])
@login_required
@admin_page_required
def update_profile(user_id):
    subject = User.query.get_or_404(user_id)
    form = {key: request.form.get(key, "").strip() for key in ("first_name", "last_name", "username", "email")}
    try:
        changed = directory.update_identity(subject, actor_id=current_user.id, **form)
    except ValidationError as exc:
        flash(str(exc), "error")
        return _render(subject, "profile", status=400, edit_open=True, form=form)

    flash(f"Updated {', '.join(c.replace('_', ' ') for c in changed)}." if changed else "Nothing to change.", "success")
    return redirect(_page_url(user_id, "profile"))


@admin_users_bp.route("/<int:user_id>/access", methods=["POST"])
@login_required
@admin_page_required
def update_access(user_id):
    subject = User.query.get_or_404(user_id)
    if subject.id == current_user.id:
        flash("You cannot change your own role, so an administrator is never locked out.", "error")
        return redirect(_page_url(user_id, "access"))
    try:
        changed = directory.change_role(subject, request.form.get("role", ""), current_user.id)
    except ValidationError as exc:
        flash(str(exc), "error")
        return redirect(_page_url(user_id, "access"))

    flash(f"Role changed to {directory.ROLE_LABELS[subject.role]}." if changed else "That is already their role.", "success")
    return redirect(_page_url(user_id, "access"))


@admin_users_bp.route("/<int:user_id>/authentication/password", methods=["POST"])
@login_required
@admin_page_required
def reset_password(user_id):
    subject = User.query.get_or_404(user_id)
    try:
        directory.reset_password(
            subject, request.form.get("password", ""), request.form.get("confirm_password", ""), current_user.id
        )
    except ValidationError as exc:
        flash(str(exc), "error")
        return redirect(_page_url(user_id, "authentication"))

    flash("Password reset. Share it with the user securely; their trusted devices were signed out.", "success")
    return redirect(_page_url(user_id, "authentication"))


@admin_users_bp.route("/<int:user_id>/authentication/lock", methods=["POST"])
@login_required
@admin_page_required
def toggle_lock(user_id):
    subject = User.query.get_or_404(user_id)
    if subject.id == current_user.id:
        flash("You cannot lock your own account.", "error")
        return redirect(_page_url(user_id, "authentication"))

    lock = subject.is_active_flag
    directory.set_locked(subject, lock, current_user.id)
    flash(f"{'Locked' if lock else 'Unlocked'} {subject.username}.", "success")
    return redirect(_page_url(user_id, "authentication"))


@admin_users_bp.route("/<int:user_id>/authentication/revoke", methods=["POST"])
@login_required
@admin_page_required
def revoke_devices(user_id):
    subject = User.query.get_or_404(user_id)
    directory.revoke_trusted_devices(subject, current_user.id)
    flash("Trusted devices reset. They will be asked for an email code at their next sign-in.", "success")
    return redirect(_page_url(user_id, "authentication"))
