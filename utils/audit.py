from sqlalchemy import func

from extensions import db
from models import AuditLog


def log_action(user_id, action, detail=None):
    """Write an audit log entry. Never pass password values as `detail`."""
    entry = AuditLog(user_id=user_id, action=action, detail=detail)
    db.session.add(entry)
    db.session.commit()
    return entry


def latest_entry_time(actions, user_id=None, detail=None):
    """Timestamp of the newest audit entry with one of `actions` (optionally for
    one user and/or with exactly this detail), or None if there is none."""
    query = db.session.query(func.max(AuditLog.timestamp)).filter(AuditLog.action.in_(actions))
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if detail is not None:
        query = query.filter(AuditLog.detail == detail)
    return query.scalar()
