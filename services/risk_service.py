from sqlalchemy import func

from extensions import db
from models import Asset, AuthorizedTarget, Vulnerability

# Fallback weight (roughly matching a CVSS base score) used only when a
# finding has no real CVSS score attached -- e.g. Nuclei template matches,
# which report a severity bucket but not a numeric score.
_SEVERITY_WEIGHTS = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}

# A CVE CISA's KEV catalog lists is confirmed actively exploited in the
# wild -- the strongest real-world risk signal available, well beyond
# CVSS alone, so it gets the larger boost. A publicly known exploit/PoC
# (via CIRCL) without confirmed in-the-wild use is a smaller boost: it
# raises the odds of exploitation without confirming it's already
# happening. See services/kev_service.py and services/cve_lookup.py.
_KEV_MULTIPLIER = 1.5
_EXPLOIT_MULTIPLIER = 1.2

# Findings in these statuses no longer represent live risk.
_LIVE_STATUSES = ("open", "in_progress")


def severity_counts(target_id=None):
    query = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
    if target_id is not None:
        query = query.join(Asset).filter(Asset.target_id == target_id)
    counts = {severity: 0 for severity in _SEVERITY_WEIGHTS}
    for severity, count in query.group_by(Vulnerability.severity).all():
        counts[severity] = count
    return counts


def vulnerability_priority(vuln: Vulnerability) -> float:
    """Per-finding priority score: real CVSS score when known (falling
    back to a severity-bucket weight otherwise), boosted when CISA's KEV
    catalog confirms active exploitation, or a public exploit is known to
    exist. This is the same score used to sort the Threat Intelligence
    findings list, not just a UI label.
    """
    base = vuln.cvss_score if vuln.cvss_score is not None else _SEVERITY_WEIGHTS.get(vuln.severity, 1.0)
    if vuln.kev:
        return round(base * _KEV_MULTIPLIER, 2)
    if vuln.exploit_available:
        return round(base * _EXPLOIT_MULTIPLIER, 2)
    return round(base, 2)


def _live_vulnerabilities_query(target_id=None):
    query = Vulnerability.query.filter(Vulnerability.status.in_(_LIVE_STATUSES))
    if target_id is not None:
        query = query.join(Asset).filter(Asset.target_id == target_id)
    return query


def risk_score(target_id=None) -> int:
    vulns = _live_vulnerabilities_query(target_id).all()
    return round(sum(vulnerability_priority(v) for v in vulns))


def dashboard_summary():
    total_assets = db.session.query(func.count(Asset.id)).scalar() or 0
    total_targets = db.session.query(func.count(AuthorizedTarget.id)).scalar() or 0
    counts = severity_counts()
    return {
        "total_assets": total_assets,
        "total_targets": total_targets,
        "vulnerabilities": counts,
        "total_vulnerabilities": sum(counts.values()),
        "risk_score": risk_score(),
    }
