"""Progress of one scan chain, worked out from the phases that have really run.

A chain is: asset discovery, then for every asset a port scan, a vulnerability
scan and a dork exposure check (see scan_service.run_scan_chain). How many
assets there are is only known once discovery has finished, so until then the
progress is unknown (None) and the UI shows a moving "working" bar instead of
a made-up percentage. Afterwards progress is finished phases / total phases.
"""

from models import Asset, Scan

TERMINAL_STATUSES = ("completed", "failed", "stopped")

PHASE_LABELS = {
    "port_discovery": "Port discovery",
    "vulnerability_scan": "Vulnerability scan",
    "dork_scan": "Dork exposure check",
}
PHASES_PER_ASSET = len(PHASE_LABELS)


def chain_progress(lead: Scan) -> dict:
    """{"percent": int | None, "phase": str, "finished_at": datetime | None}
    for the chain started by `lead` (its asset_discovery scan). `percent` never
    reaches 100 here; the caller decides when the whole chain is done."""
    if lead.status not in TERMINAL_STATUSES:
        return {"percent": None, "phase": "Discovering assets", "finished_at": None}

    phases = (
        Scan.query.filter(
            Scan.target_id == lead.target_id,
            Scan.id > lead.id,
            Scan.scan_type.in_(tuple(PHASE_LABELS)),
        )
        .order_by(Scan.id)
        .all()
    )
    asset_count = Asset.query.filter_by(target_id=lead.target_id).count()
    total = 1 + PHASES_PER_ASSET * max(asset_count, 1)
    finished = [s for s in phases if s.status in TERMINAL_STATUSES]
    percent = min(99, (1 + len(finished)) * 100 // total)

    running = next((s for s in reversed(phases) if s.status == "running"), None)
    if running is not None:
        current_asset = min(sum(1 for s in phases if s.scan_type == "port_discovery"), max(asset_count, 1))
        phase = f"{PHASE_LABELS[running.scan_type]} · asset {current_asset} of {max(asset_count, 1)}"
    else:
        phase = "Working"

    ended = [s.completed_at for s in [lead, *finished] if s.completed_at]
    return {"percent": percent, "phase": phase, "finished_at": max(ended) if ended else None}
