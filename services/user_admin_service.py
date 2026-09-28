"""Business logic behind the IT Administrator's user directory
(routes/admin_users.py): editing a user's identity, role and sign-in security,
and reading their targets and activity.

Nothing here decides who is allowed to call it; the routes do that. Every
change writes an audit entry whose detail starts with `target_user_id=<id>`,
which is how a user's Activity tab finds "what was done to this account".
"""

from extensions import db
from models import (
    ROLE_ANALYST,
    ROLE_IT_ADMIN,
    ROLE_THREAT_INTEL,
    ROLES,
    Asset,
    AuditLog,
    AuthorizedTarget,
    User,
    Vulnerability,
)
from utils.audit import latest_entry_time, log_action
from utils.device_trust import REVOKE_ACTIONS, revocation_detail
from utils.validators import (
    ValidationError,
    validate_email,
    validate_password,
    validate_role,
    validate_username,
)

TABS = (
    ("profile", "Profile"),
    ("access", "Access"),
    ("targets", "Targets"),
    ("authentication", "Authentication"),
    ("activity", "Activity"),
)

ROLE_LABELS = {
    ROLE_IT_ADMIN: "IT Administrator",
    ROLE_ANALYST: "Cybersecurity Analyst",
    ROLE_THREAT_INTEL: "Threat Intelligence Analyst",
}

ROLE_CAPABILITIES = {
    ROLE_IT_ADMIN: (
        "Manage user accounts, roles and sign-in security (this directory)",
        "Delete authorized targets",
        "Run scans and change finding status through the API",
        "View the Threat Intelligence page",
    ),
    ROLE_ANALYST: (
        "Add authorized targets and run scans: Subfinder, Nmap, Nuclei and the Google dork exposure check",
        "Work with inventory, findings and Google dorking for their own targets",
        "Triage findings (open, in progress, resolved, false positive) and delete them",
        "Generate PDF and CSV reports",
    ),
    ROLE_THREAT_INTEL: (
        "View live findings across every authorized target (read-only)",
        "See CISA KEV matches and findings ranked by CVSS, KEV and public exploits",
        "Export the Threat Briefing (CSV)",
        "Cannot add targets, run scans, change finding status or generate scan reports",
    ),
}

_LIVE_STATUSES = ("open", "in_progress")


# ------------------------------------------------------------------ display
def display_name(user: User) -> str:
    return " ".join(p for p in (user.first_name, user.last_name) if p) or user.username


def initials(user: User) -> str:
    if user.first_name and user.last_name:
        return (user.first_name[0] + user.last_name[0]).upper()
    return user.username[:2].upper()


def last_sign_in(user_id: int):
    return latest_entry_time(("login_success",), user_id=user_id)


def trusted_devices_reset_at(user_id: int):
    return latest_entry_time(REVOKE_ACTIONS, detail=revocation_detail(user_id))


# ------------------------------------------------------------------ changes
def update_identity(user: User, first_name: str, last_name: str, username: str, email: str, actor_id: int) -> list:
    """Change name, username and email. Returns the names of the fields that changed."""
    first_name, last_name = (first_name or "").strip(), (last_name or "").strip()
    if not first_name or not last_name:
        raise ValidationError("First and last name are required.")
    if max(len(first_name), len(last_name)) > 80:
        raise ValidationError("Names can be at most 80 characters.")
    username = validate_username(username)
    email = validate_email(email)

    taken = User.query.filter(User.username == username, User.id != user.id).first()
    if taken:
        raise ValidationError("That username is already taken.")
    taken = User.query.filter(User.email == email, User.id != user.id).first()
    if taken:
        raise ValidationError("An account with that email already exists.")

    proposed = {"first_name": first_name, "last_name": last_name, "username": username, "email": email}
    changed = [field for field, value in proposed.items() if getattr(user, field) != value]
    if not changed:
        return []

    for field in changed:
        setattr(user, field, proposed[field])
    db.session.commit()
    log_action(actor_id, "user_identity_updated", detail=f"target_user_id={user.id} changed={','.join(changed)}")
    return changed


def change_role(user: User, new_role: str, actor_id: int) -> bool:
    """Returns False when the user already has that role."""
    validate_role(new_role, ROLES)
    if user.role == new_role:
        return False
    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_action(actor_id, "user_role_updated", detail=f"target_user_id={user.id} role={old_role}->{new_role}")
    return True


def reset_password(user: User, password: str, confirm: str, actor_id: int) -> None:
    """Set a new password. Also cancels the user's trusted devices, so their next
    sign-in must pass the email code again. Never logs the password."""
    validate_password(password)
    if password != confirm:
        raise ValidationError("Passwords do not match.")
    user.set_password(password)
    db.session.commit()
    log_action(actor_id, "password_reset_by_admin", detail=revocation_detail(user.id))


def set_locked(user: User, locked: bool, actor_id: int) -> None:
    user.is_active_flag = not locked
    db.session.commit()
    log_action(actor_id, "user_locked" if locked else "user_unlocked", detail=f"target_user_id={user.id}")


def revoke_trusted_devices(user: User, actor_id: int) -> None:
    log_action(actor_id, "mfa_reset", detail=revocation_detail(user.id))


# ------------------------------------------------------------------ reading
def targets_summary(user_id: int) -> list:
    """The user's authorized targets with asset and live-finding counts."""
    rows = []
    targets = AuthorizedTarget.query.filter_by(owner_id=user_id).order_by(AuthorizedTarget.created_at.desc()).all()
    for target in targets:
        asset_count = Asset.query.filter_by(target_id=target.id).count()
        live_findings = (
            Vulnerability.query.join(Asset)
            .filter(Asset.target_id == target.id, Vulnerability.status.in_(_LIVE_STATUSES))
            .count()
        )
        rows.append(
            {
                "domain": target.domain,
                "authorized": target.authorized,
                "assets": asset_count,
                "live_findings": live_findings,
                "created_at": target.created_at,
            }
        )
    return rows


def _pretty_action(action: str) -> str:
    return action.replace("_", " ").capitalize()


def _entries(query, limit: int, viewer_id: int = None) -> list:
    entries = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(limit).all()
    actor_ids = {e.user_id for e in entries if e.user_id}
    names = {u.id: u.username for u in User.query.filter(User.id.in_(actor_ids)).all()} if actor_ids else {}
    return [
        {
            "timestamp": e.timestamp,
            "action": _pretty_action(e.action),
            "detail": e.detail or "",
            "actor": "This user" if e.user_id == viewer_id and viewer_id else names.get(e.user_id, "system / anonymous"),
        }
        for e in entries
    ]


def activity_for(user_id: int, limit: int = 50) -> list:
    """Things the user did, plus admin changes made to their account."""
    about = (
        AuditLog.detail.like(f"%user_id={user_id}")
        | AuditLog.detail.like(f"%user_id={user_id} %")
    )
    return _entries(AuditLog.query.filter((AuditLog.user_id == user_id) | about), limit, viewer_id=user_id)


def recent_activity(limit: int = 10) -> list:
    return _entries(AuditLog.query, limit)
