from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from models import ROLE_IT_ADMIN, ROLE_THREAT_INTEL
from services import inventory_service
from services.dork_service import total_dork_count

inventory_bp = Blueprint("inventory", __name__, url_prefix="/workspace")


@inventory_bp.route("/<slug>")
@login_required
def inventory_page(slug):
    page = inventory_service.PAGES.get(slug)
    if page is None:
        abort(404)
    if current_user.role == ROLE_IT_ADMIN:
        return redirect(url_for("auth_pages.admin_dashboard"))
    if current_user.role == ROLE_THREAT_INTEL:
        return redirect(url_for("threat_intel.threat_intel_page"))

    targets = inventory_service.owned_targets(current_user.id)
    owned_ids = {t.id for t in targets}
    requested = request.args.get("target_id", type=int)
    selected_target_id = requested if requested in owned_ids else None
    scoped = [t for t in targets if t.id == selected_target_id] if selected_target_id else targets

    columns, rows = inventory_service.build_page(slug, scoped)
    return render_template(
        "inventory.html",
        active_nav=f"inv-{slug}",
        user=current_user,
        slug=slug,
        page=page,
        columns=columns,
        rows=rows,
        targets=targets,
        selected_target_id=selected_target_id,
        selected_domain=next((t.domain for t in targets if t.id == selected_target_id), None),
        nav_counts=inventory_service.nav_counts(targets),
        dork_count=total_dork_count(),
    )
