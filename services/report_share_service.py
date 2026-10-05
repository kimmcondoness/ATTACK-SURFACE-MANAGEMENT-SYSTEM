"""Sharing an exported report with Threat Intelligence.

A Cybersecurity Analyst shares a report from their report history; every Threat Intelligence
analyst then finds it in the "Reports shared by analysts" inbox and downloads the very same
file (nothing is copied or regenerated). A report is shared at most once, can be withdrawn by
its owner, and the analyst can see whether Threat Intelligence has opened it.

Who opened what is read back from the audit log (the same way report_service.opened_report_ids
does for the analyst's own downloads), so no extra bookkeeping table is needed.
"""

import os
import re
from typing import Optional

from sqlalchemy.exc import IntegrityError

from extensions import db
from models import AuditLog, AuthorizedTarget, Report, ReportShare, User
from services.user_admin_service import display_name
from utils.audit import log_action

NOTE_MAX_LENGTH = 500
DOWNLOAD_ACTION = "shared_report_downloaded"
_SHARE_ID = re.compile(r"share_id=(\d+)")


def share_report(report: Report, shared_by: int, note: Optional[str] = None):
    """Share `report` with Threat Intelligence. Returns (share, created); sharing a report that is
    already shared changes nothing and returns the existing share with created=False."""
    existing = ReportShare.query.filter_by(report_id=report.id).first()
    if existing:
        return existing, False

    share = ReportShare(report_id=report.id, shared_by=shared_by, note=(note or "").strip()[:NOTE_MAX_LENGTH] or None)
    db.session.add(share)
    try:
        db.session.commit()
    except IntegrityError:   # a second click raced the first: it is shared, which is all that was asked
        db.session.rollback()
        return ReportShare.query.filter_by(report_id=report.id).one(), False
    log_action(shared_by, "report_shared", detail=f"report_id={report.id} share_id={share.id}")
    return share, True


def withdraw_share(report_id: int, actor_id: int) -> bool:
    """Take a report back out of the Threat Intelligence inbox. False if it was not shared."""
    share = ReportShare.query.filter_by(report_id=report_id).first()
    if not share:
        return False
    db.session.delete(share)
    db.session.commit()
    log_action(actor_id, "report_share_withdrawn", detail=f"report_id={report_id}")
    return True


def shares_by_report(report_ids) -> dict:
    """{report_id: ReportShare} for those of `report_ids` that are shared."""
    if not report_ids:
        return {}
    return {s.report_id: s for s in ReportShare.query.filter(ReportShare.report_id.in_(list(report_ids))).all()}


def downloaded_share_ids(user_id: Optional[int] = None) -> set:
    """Ids of shares that have been downloaded: by `user_id`, or by anyone when it is None."""
    query = AuditLog.query.filter_by(action=DOWNLOAD_ACTION)
    if user_id is not None:
        query = query.filter_by(user_id=user_id)
    matches = (_SHARE_ID.fullmatch(detail or "") for (detail,) in query.with_entities(AuditLog.detail).all())
    return {int(m.group(1)) for m in matches if m}


def inbox(limit: int = 100) -> list:
    """The shared reports, newest first, with what the inbox shows about each."""
    rows = (
        db.session.query(ReportShare, Report, AuthorizedTarget)
        .join(Report, Report.id == ReportShare.report_id)
        .outerjoin(AuthorizedTarget, AuthorizedTarget.id == Report.target_id)
        .order_by(ReportShare.shared_at.desc(), ReportShare.id.desc())
        .limit(limit)
        .all()
    )
    sharers = {u.id: u for u in User.query.filter(User.id.in_({share.shared_by for share, _, _ in rows})).all()} if rows else {}
    return [
        {
            "share": share,
            "report": report,
            "domain": target.domain if target else "(removed target)",
            "shared_by": display_name(sharers[share.shared_by]) if share.shared_by in sharers else "a former user",
            "available": os.path.exists(report.file_path),
        }
        for share, report, target in rows
    ]


def get_shared(share_id: int):
    """(share, report) for a share, or None if there is no such share or its report is gone."""
    share = db.session.get(ReportShare, share_id)
    report = db.session.get(Report, share.report_id) if share else None
    return (share, report) if report else None
