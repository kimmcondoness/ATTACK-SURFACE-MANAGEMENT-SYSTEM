from ariadne import ObjectType, QueryType, make_executable_schema

from models import Asset, AuthorizedTarget, Scan, Vulnerability
from services import job_registry
from services.chart_service import normalize_range, scan_status_totals, severity_totals
from services.risk_service import risk_score
from services.target_service import list_target_ids_for_owner

type_defs = """
    type Query {
        scanStatus(scanId: Int!): ScanStatus
        liveCharts(range: String, targetId: Int): LiveCharts!
        recentFindings(limit: Int): [Finding!]!
    }

    type ScanStatus {
        scanId: Int!
        status: String!
        resultSummary: String
        source: String
        targetDomain: String!
        paused: Boolean!
    }

    type LiveCharts {
        scanStatusTotals: [ChartSegment!]!
        severityTotals: [ChartSegment!]!
        totalTargets: Int!
        totalAssets: Int!
        vulnerableCount: Int!
        needsReviewCount: Int!
        riskScore: Int!
    }

    type ChartSegment {
        key: String!
        value: Int!
    }

    type Finding {
        id: Int!
        severity: String!
        cve: String
        title: String!
        status: String!
        targetDomain: String!
        discoveredAt: String
    }
"""

query = QueryType()
scan_status_type = ObjectType("ScanStatus")
live_charts_type = ObjectType("LiveCharts")


def _owned_scan(scan_id, user):
    scan = Scan.query.get(scan_id)
    if not scan:
        return None
    target = AuthorizedTarget.query.get(scan.target_id)
    if not target or (target.owner_id != user.id and user.role != "it_admin"):
        return None
    return scan, target


@query.field("scanStatus")
def resolve_scan_status(_, info, scanId):
    user = info.context["user"]
    owned = _owned_scan(scanId, user)
    if not owned:
        return None
    scan, target = owned
    control = job_registry.get_control(scanId)
    paused = bool(control and control.is_paused())

    # The lead (asset_discovery) row can finish in seconds while the rest
    # of the chain (port + vulnerability scans) keeps running for minutes
    # in the background thread -- so "is the job actually done" has to
    # come from whether that thread is still alive, not from one phase's
    # own row, or the UI would report "completed" while work is still
    # happening.
    if job_registry.is_running(scanId):
        status = "paused" if paused else "running"
    else:
        status = scan.status

    return {
        "scanId": scan.id,
        "status": status,
        "resultSummary": scan.result_summary,
        "source": scan.source,
        "targetDomain": target.domain,
        "paused": paused,
    }


def _to_segments(totals: dict):
    return [{"key": key, "value": value} for key, value in totals.items()]


@query.field("liveCharts")
def resolve_live_charts(_, info, range=None, targetId=None):
    user = info.context["user"]
    range_key = normalize_range(range)
    owned_target_ids = list_target_ids_for_owner(user.id)
    target_ids = [targetId] if targetId in owned_target_ids else owned_target_ids

    targets = AuthorizedTarget.query.filter(AuthorizedTarget.id.in_(target_ids)).all() if target_ids else []
    assets = [a for t in targets for a in t.assets]
    findings = (
        Vulnerability.query.join(Asset).filter(Asset.target_id.in_(target_ids)).all() if target_ids else []
    )

    return {
        "scanStatusTotals": _to_segments(scan_status_totals(target_ids, range_key)),
        "severityTotals": _to_segments(severity_totals(target_ids, range_key)),
        "totalTargets": len(targets),
        "totalAssets": len(assets),
        "vulnerableCount": sum(1 for f in findings if f.status == "open"),
        "needsReviewCount": sum(1 for f in findings if f.status == "in_progress"),
        "riskScore": sum(risk_score(t.id) for t in targets),
    }


@query.field("recentFindings")
def resolve_recent_findings(_, info, limit=10):
    user = info.context["user"]
    target_ids = list_target_ids_for_owner(user.id)
    if not target_ids:
        return []

    target_map = {t.id: t.domain for t in AuthorizedTarget.query.filter(AuthorizedTarget.id.in_(target_ids)).all()}
    findings = (
        Vulnerability.query.join(Asset)
        .filter(Asset.target_id.in_(target_ids))
        .order_by(Vulnerability.discovered_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "cve": f.cve,
            "title": f.title,
            "status": f.status,
            "targetDomain": target_map.get(f.asset.target_id, "unknown"),
            "discoveredAt": f.discovered_at.isoformat() if f.discovered_at else None,
        }
        for f in findings
    ]


schema = make_executable_schema(type_defs, query)
