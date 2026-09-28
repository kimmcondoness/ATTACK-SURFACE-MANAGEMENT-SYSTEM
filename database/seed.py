import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from extensions import db
from sqlalchemy import text

from models import ROLE_ANALYST, ROLE_IT_ADMIN, SCAN_TYPES, User

LEGACY_SECURITY_TEAM_ROLE = "security_team"

# Before real configuration checks existed, a scan on a machine without Nuclei stored these two
# made-up findings. They are recognised by their exact title and wording, never by title alone.
SAMPLE_FINDINGS = (
    ("Missing security headers", "does not set recommended security headers (CSP, X-Frame-Options)."),
    ("Server version disclosure", "exposes server version information in HTTP response headers."),
)


def remove_sample_findings() -> int:
    """Delete findings left over from the old built-in sample data. Only runs when asked
    (python database/seed.py --remove-sample-findings); real findings are never matched."""
    from models import Vulnerability

    removed = 0
    for title, wording in SAMPLE_FINDINGS:
        for vuln in Vulnerability.query.filter(Vulnerability.title == title, Vulnerability.description.like(f"%{wording}")).all():
            db.session.delete(vuln)
            removed += 1
    db.session.commit()
    return removed


def migrate_legacy_roles():
    moved = User.query.filter_by(role=LEGACY_SECURITY_TEAM_ROLE).update({"role": ROLE_ANALYST})
    db.session.commit()
    if moved:
        print(f"Moved {moved} legacy security_team user(s) to cybersecurity_analyst.")


def migrate_scan_type_constraint():
    """MySQL only. Databases created before the dork exposure check have a
    CHECK constraint on scans.scan_type that rejects 'dork_scan', so widen it
    to the current SCAN_TYPES. Safe to run repeatedly."""
    if db.engine.dialect.name != "mysql":
        return
    old_clause = db.session.execute(
        text(
            "SELECT check_clause FROM information_schema.check_constraints "
            "WHERE constraint_schema = DATABASE() AND constraint_name = 'chk_scans_type'"
        )
    ).scalar()
    if old_clause is None or "dork_scan" in old_clause:
        return

    allowed = ", ".join(f"'{t}'" for t in SCAN_TYPES)
    old_allowed = ", ".join(f"'{t}'" for t in SCAN_TYPES if t != "dork_scan")
    db.session.execute(text("ALTER TABLE scans DROP CHECK chk_scans_type"))
    try:
        db.session.execute(text(f"ALTER TABLE scans ADD CONSTRAINT chk_scans_type CHECK (scan_type IN ({allowed}))"))
    except Exception:
        db.session.execute(text(f"ALTER TABLE scans ADD CONSTRAINT chk_scans_type CHECK (scan_type IN ({old_allowed}))"))
        raise
    db.session.commit()
    print("Widened chk_scans_type to allow dork_scan.")


def seed():
    app = create_app()
    with app.app_context():
        db.create_all()
        migrate_legacy_roles()
        migrate_scan_type_constraint()

        username = os.environ.get("SEED_ADMIN_USERNAME", "admin")
        email = os.environ.get("SEED_ADMIN_EMAIL", "admin@example.com")
        password = os.environ.get("SEED_ADMIN_PASSWORD", "ChangeMe123!")

        if User.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists. Skipping seed.")
            return

        admin = User(username=username, email=email, role=ROLE_IT_ADMIN)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Seeded IT Admin user '{username}'.")


if __name__ == "__main__":
    if "--remove-sample-findings" in sys.argv:
        with create_app().app_context():
            print(f"Removed {remove_sample_findings()} sample finding(s) left over from the old built-in sample data.")
    else:
        seed()
