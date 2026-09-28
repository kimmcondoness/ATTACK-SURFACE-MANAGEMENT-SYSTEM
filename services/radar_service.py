"""Data for the live radar on the analyst dashboard.

The radar is a picture of the attack surface as it stands: every asset is a
dot, placed on a ring by the worst live (open or in-progress) finding on it, so
the riskiest assets sit closest to the centre. Nothing here is invented; a
target with no assets yields an empty radar.
"""

from collections import defaultdict
from datetime import datetime

from sqlalchemy import func

from extensions import db
from models import Asset, AuthorizedTarget, PortService, Vulnerability
from services.risk_service import vulnerability_priority

_LIVE_STATUSES = ("open", "in_progress")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
_MAX_CALLOUTS = 3
_CALLOUT_TITLE_LENGTH = 44


def _host(asset: Asset) -> str:
    return asset.subdomain or asset.url or asset.ip_address or f"asset-{asset.id}"


def _short(title: str) -> str:
    title = title or ""
    return title if len(title) <= _CALLOUT_TITLE_LENGTH else title[: _CALLOUT_TITLE_LENGTH - 1].rstrip() + "…"


def radar_snapshot(owner_id: int, target_id: int = None, max_assets: int = 150) -> dict:
    """Assets, callouts and headline numbers for one owner, or for one of their targets."""
    targets = AuthorizedTarget.query.filter_by(owner_id=owner_id).all()
    owned = {t.id: t for t in targets}
    if target_id in owned:
        target_ids, scope = [target_id], owned[target_id].domain
    else:
        target_ids, scope = list(owned), "All targets"

    assets = Asset.query.filter(Asset.target_id.in_(target_ids)).all() if target_ids else []
    live = (
        Vulnerability.query.join(Asset)
        .filter(Asset.target_id.in_(target_ids), Vulnerability.status.in_(_LIVE_STATUSES))
        .all()
        if target_ids
        else []
    )

    findings_by_asset = defaultdict(list)
    for vuln in live:
        findings_by_asset[vuln.asset_id].append(vuln)

    port_counts = {}
    if assets:
        rows = (
            db.session.query(PortService.asset_id, func.count(PortService.id))
            .filter(PortService.asset_id.in_([a.id for a in assets]))
            .group_by(PortService.asset_id)
            .all()
        )
        port_counts = dict(rows)

    nodes = []
    for asset in assets:
        found = findings_by_asset.get(asset.id, [])
        worst = min((v.severity for v in found), key=lambda s: _SEVERITY_RANK.get(s, 4), default="none")
        nodes.append(
            {
                "id": asset.id,
                "host": _host(asset),
                "severity": worst,
                "findings": len(found),
                "ports": port_counts.get(asset.id, 0),
                "target": owned[asset.target_id].domain,
            }
        )
    nodes.sort(key=lambda n: (_SEVERITY_RANK.get(n["severity"], 4), n["host"]))
    shown = nodes[:max_assets]
    shown_ids = {n["id"] for n in shown}

    top = sorted(live, key=vulnerability_priority, reverse=True)
    callouts = [
        {"asset_id": v.asset_id, "title": _short(v.title), "severity": v.severity}
        for v in top
        if v.asset_id in shown_ids
    ][:_MAX_CALLOUTS]

    return {
        "scope": scope,
        "assets": shown,
        "callouts": callouts,
        "stats": {
            "assets": len(nodes),
            "critical_risks": sum(1 for v in live if v.severity in ("critical", "high")),
            "active_alerts": len(live),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
