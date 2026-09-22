from datetime import datetime

from extensions import db
from models import Asset, PortService, SEVERITIES, Scan
from scanner.base import ScanControl
from scanner.nmap_scanner import NmapScanner
from scanner.nuclei_scanner import NucleiScanner
from scanner.subfinder import SubfinderScanner
from services.asset_service import get_or_create_self_asset, store_discovered_assets, store_ports_for_asset
from services.cve_lookup import exploit_available as check_exploit_available, lookup_cves_for_query
from services.kev_service import is_kev
from services.vulnerability_service import store_vulnerabilities_for_asset

_CVE_MATCH_NOTE = (
    "Matched via an NVD keyword search on the detected service/version banner, not a "
    "confirmed CPE match -- verify this CVE actually applies to the exact software "
    "version in use before treating it as confirmed."
)


class UnauthorizedTargetError(Exception):
    """Raised when a scan is requested against a target that is not
    marked Authorized=True. Enforced here (service layer) so it cannot
    be bypassed by calling services directly instead of going through
    an HTTP route.
    """


def _require_authorized(target):
    if target is None:
        raise UnauthorizedTargetError("Target not found.")
    if not target.authorized:
        raise UnauthorizedTargetError(
            f"Target '{target.domain}' is not authorized for scanning."
        )


def _start_scan_record(target_id: int, scan_type: str, user_id: int) -> Scan:
    scan = Scan(target_id=target_id, scan_type=scan_type, status="running", started_by=user_id)
    db.session.add(scan)
    db.session.commit()
    return scan


def _finish_scan_record(scan: Scan, status: str, source: str, summary: str):
    scan.status = status
    scan.source = source
    scan.result_summary = summary
    scan.completed_at = datetime.utcnow()
    db.session.commit()
    return scan


def run_asset_discovery(target, user_id: int, control: ScanControl = None, scan: Scan = None) -> Scan:
    _require_authorized(target)
    if scan is None:
        scan = _start_scan_record(target.id, "asset_discovery", user_id)
    else:
        scan.status = "running"
        db.session.commit()

    result = SubfinderScanner().run(target.domain, control=control)
    if result.stopped:
        return _finish_scan_record(scan, "stopped", result.source, "Stopped by user.")
    if not result.success:
        return _finish_scan_record(scan, "failed", result.source, result.error)

    created = store_discovered_assets(target.id, result.data)
    return _finish_scan_record(
        scan, "completed", result.source, f"{len(created)} assets discovered."
    )


def run_port_discovery(target, asset: Asset, user_id: int, control: ScanControl = None) -> Scan:
    _require_authorized(target)
    scan = _start_scan_record(target.id, "port_discovery", user_id)

    scan_host = asset.ip_address or asset.subdomain or target.domain
    result = NmapScanner().run(scan_host, control=control)
    if result.stopped:
        return _finish_scan_record(scan, "stopped", result.source, "Stopped by user.")
    if not result.success:
        return _finish_scan_record(scan, "failed", result.source, result.error)

    created = store_ports_for_asset(asset.id, result.data)
    return _finish_scan_record(
        scan, "completed", result.source, f"{len(created)} open ports found on {scan_host}."
    )


def _cve_lookup_findings(asset: Asset, control: ScanControl = None):
    """Best-effort NVD keyword lookup against each open port's detected
    service/version banner. Independent of whether Nuclei is installed or
    running in mock mode -- this is real external data whenever a port
    scan produced a real (non-mock) service banner to search on.
    """
    findings = []
    for port in PortService.query.filter_by(asset_id=asset.id).all():
        if control and control.stop_requested():
            break
        if control:
            control.wait_if_paused()
        if not port.service_name or port.service_name == "unknown":
            continue

        query = f"{port.service_name} {port.service_version or ''}".strip()
        for match in lookup_cves_for_query(query):
            severity = match["severity"] if match["severity"] in SEVERITIES else "medium"
            label = port.service_name + (f" {port.service_version}" if port.service_version else "")
            cve_id = match["cve_id"]
            kev_flag = is_kev(cve_id)
            has_exploit = kev_flag or check_exploit_available(cve_id)
            title = f"Possible {cve_id} affecting {label} (port {port.port})"
            if kev_flag:
                title = f"[CISA KEV] {title}"
            findings.append(
                {
                    "severity": severity,
                    "cve": cve_id,
                    "title": title,
                    "description": match["description"][:500],
                    "recommendation": _CVE_MATCH_NOTE,
                    "cvss_score": match["score"],
                    "kev": kev_flag,
                    "exploit_available": has_exploit,
                }
            )
    return findings


def run_vulnerability_scan(target, asset: Asset, user_id: int, control: ScanControl = None) -> Scan:
    _require_authorized(target)
    scan = _start_scan_record(target.id, "vulnerability_scan", user_id)

    scan_target = asset.url or asset.subdomain or target.domain
    result = NucleiScanner().run(scan_target, control=control)
    if result.stopped:
        return _finish_scan_record(scan, "stopped", result.source, "Stopped by user.")
    if not result.success:
        return _finish_scan_record(scan, "failed", result.source, result.error)

    created = store_vulnerabilities_for_asset(asset.id, result.data)

    cve_matches = [] if (control and control.stop_requested()) else _cve_lookup_findings(asset, control)
    if cve_matches:
        store_vulnerabilities_for_asset(asset.id, cve_matches)

    summary = f"{len(created)} findings on {scan_target}."
    if cve_matches:
        summary += f" {len(cve_matches)} possible CVE match(es) from NVD lookup."
    return _finish_scan_record(scan, "completed", result.source, summary)


def run_scan_chain(target, user_id: int, control: ScanControl, lead_scan: Scan = None) -> Scan:
    """Full Discovery -> Port Scan -> Vulnerability Scan pipeline for one
    target, run inline on a background thread. Returns the lead
    (asset_discovery) Scan row, which the caller registers in the job
    registry as the id Pause/Resume/Stop act on. Pass an already-created
    `lead_scan` (status="pending") so the caller can hand its id back to
    the browser before the background thread does any work.

    `control` is checked between every phase (and inside each scanner's
    own run loop) so a Stop request aborts the remaining phases instead
    of just the currently-running tool.
    """
    _require_authorized(target)

    self_asset = get_or_create_self_asset(target)
    lead_scan = run_asset_discovery(target, user_id, control=control, scan=lead_scan)

    if lead_scan.status in ("stopped", "failed") or control.stop_requested():
        return lead_scan

    assets = [self_asset] + [
        a for a in Asset.query.filter_by(target_id=target.id).all() if a.id != self_asset.id
    ]

    for asset in assets:
        if control.stop_requested():
            break
        control.wait_if_paused()
        if control.stop_requested():
            break
        run_port_discovery(target, asset, user_id, control=control)

        if control.stop_requested():
            break
        control.wait_if_paused()
        if control.stop_requested():
            break
        run_vulnerability_scan(target, asset, user_id, control=control)

    return lead_scan


def list_scans_for_target(target_id: int):
    return Scan.query.filter_by(target_id=target_id).order_by(Scan.started_at.desc()).all()
