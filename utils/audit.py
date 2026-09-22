from extensions import db
from models import AuditLog


def log_action(user_id, action, detail=None):
    """Write an audit log entry. Never pass password values as `detail`."""
    entry = AuditLog(user_id=user_id, action=action, detail=detail)
    db.session.add(entry)
    db.session.commit()
    return entry
