from datetime import datetime

from extensions import db
from models import Asset, PortService, SEVERITIES, Scan
from scanner.base import ScanControl
from scanner.config_scanner import TITLE_PREFIX as CONFIG_PREFIX, ConfigScanner
from scanner.exposure_scanner import TITLE_PREFIX as DORK_PREFIX, ExposureScanner
from scanner.nmap_scanner import NmapScanner
from scanner.nuclei_scanner import NucleiScanner
from scanner.subfinder import SubfinderScanner
from services import monitor_service
from services.asset_service import (
    get_or_create_self_asset,
    record_asset_ip,
    store_ports_for_asset,
)
from services.cve_lookup import exploit_available as check_exploit_available, lookup_cves_for_query
from services.kev_service import is_kev

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

    real = result.source == "real"
    created = monitor_service.sync_discovered_assets(
        target,
        result.data,
        trustworthy=real and bool(result.data),   # a made-up or empty result must never mark real hosts missing
        baseline=(not real) or monitor_service.is_first_discovery(target.id, scan.id),
    )
    known = len({(i.get("subdomain") or "").lower() for i in result.data}) - len(created)
    summary = f"{len(created)} assets discovered." if not known else f"{len(created)} new asset(s) discovered, {known} already known."
    return _finish_scan_record(scan, "completed", result.source, summary)


def run_port_discovery(target, asset: Asset, user_id: int, control: ScanControl = None) -> Scan:
    _require_authorized(target)
    scan = _start_scan_record(target.id, "port_discovery", user_id)

    # Hostname first: scanning by a stored IP would lose the vhost/SNI a CDN or
    # shared host routes on, and give different results.
    scan_host = asset.subdomain or asset.ip_address or target.domain
    result = NmapScanner().run(scan_host, control=control)
    if result.stopped:
        return _finish_scan_record(scan, "stopped", result.source, "Stopped by user.")
    if not result.success:
        return _finish_scan_record(scan, "failed", result.source, result.error)

    created = store_ports_for_asset(asset.id, result.data)
    # Mock results carry no raw output, so this never records a made-up IP.
    record_asset_ip(asset, NmapScanner.extract_host_ip(result.raw_output))
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
    """Look for vulnerabilities and misconfigurations on one asset.

    Always runs the built-in configuration checks (HTTPS and TLS, security headers, information
    disclosure, cookies, CORS) and the NVD lookup on the detected service banners; when Nuclei is
    installed its template scan runs as well. Nothing here is ever made up: without Nuclei those
    checks are simply skipped, and the summary says so."""
    _require_authorized(target)
    scan = _start_scan_record(target.id, "vulnerability_scan", user_id)

    scan_target = asset.url or asset.subdomain or target.domain
    baseline = monitor_service.is_first_chain(target.id, scan.id)
    notes, nuclei_findings = [], []

    nuclei = NucleiScanner()
    if nuclei.is_available():
        nuclei_result = nuclei.run(scan_target, control=control)
        if nuclei_result.stopped:
            return _finish_scan_record(scan, "stopped", "real", "Stopped by user.")
        if nuclei_result.success:
            nuclei_findings = nuclei_result.data
        else:
            notes.append(f"Nuclei failed ({(nuclei_result.error or 'unknown error').strip()[:80]})")
    else:
        notes.append("Nuclei is not installed, so its template checks were skipped")

    if control and control.stop_requested():
        return _finish_scan_record(scan, "stopped", "real", "Stopped by user.")

    config_result = ConfigScanner().run(scan_target, control=control)
    if config_result.stopped:
        return _finish_scan_record(scan, "stopped", "real", "Stopped by user.")

    created, fixed = [], []
    if config_result.raw_output == "unreachable":
        notes.append("the host did not answer over HTTP(S), so the configuration checks were skipped")
    else:
        reconciled = monitor_service.reconcile_findings(target, asset, CONFIG_PREFIX, config_result.data, baseline)
        created += reconciled.created
        fixed += reconciled.resolved

    created += monitor_service.store_new_findings(target, asset, nuclei_findings, baseline)

    cve_matches = [] if (control and control.stop_requested()) else _cve_lookup_findings(asset, control)
    cve_created = monitor_service.store_new_findings(target, asset, cve_matches, baseline)
    created += cve_created

    summary = f"{len(created)} new finding(s) on {scan_target}."
    if cve_created:
        summary += f" {len(cve_created)} are possible CVE match(es) from NVD lookup."
    if fixed:
        summary += f" {len(fixed)} earlier finding(s) no longer detected and marked resolved."
    if notes:
        summary += " Note: " + "; ".join(notes) + "."
    return _finish_scan_record(scan, "completed", "real", summary)


def run_dork_scan(target, asset: Asset, user_id: int, control: ScanControl = None) -> Scan:
    """Confirm which Google dork exposures are real on one asset by requesting
    the matching paths on the host (see scanner/exposure_scanner.py). Every
    confirmed exposure is stored as a normal finding, so it flows into the
    Findings page, the risk score and the reports like any scanner result.
    """
    _require_authorized(target)
    scan = _start_scan_record(target.id, "dork_scan", user_id)

    host = asset.url or asset.subdomain or target.domain
    # Storage buckets are named after the domain, so check them once, on the root host.
    bucket_domain = target.domain if asset.subdomain == target.domain else None
    result = ExposureScanner().run(host, control=control, bucket_domain=bucket_domain)
    if result.stopped:
        return _finish_scan_record(scan, "stopped", result.source, "Stopped by user.")
    if not result.success:
        return _finish_scan_record(scan, "failed", result.source, result.error)
    if result.raw_output == "unreachable":
        return _finish_scan_record(scan, "completed", result.source, f"{host} did not answer over HTTP(S); exposure checks skipped.")

    baseline = monitor_service.is_first_chain(target.id, scan.id)
    reconciled = monitor_service.reconcile_findings(target, asset, DORK_PREFIX, result.data, baseline)

    already = len(result.data) - len(reconciled.created)
    summary = f"{len(reconciled.created)} exposure(s) confirmed on {host} ({result.raw_output})."
    if not result.data:
        summary = f"No exposure found on {host} ({result.raw_output})."
    if already > 0:
        summary += f" {already} already recorded."
    if reconciled.resolved:
        summary += f" {len(reconciled.resolved)} earlier exposure(s) no longer detected and marked resolved."
    return _finish_scan_record(scan, "completed", result.source, summary)


def run_scan_chain(target, user_id: int, control: ScanControl, lead_scan: Scan = None) -> Scan:
    """Full Discovery -> Port Scan -> Vulnerability Scan -> Dork exposure pipeline for one
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
        a for a in Asset.query.filter_by(target_id=target.id).all()
        if a.id != self_asset.id and a.status != "missing"   # a host discovery no longer returns is not worth scanning
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

        if control.stop_requested():
            break
        control.wait_if_paused()
        if control.stop_requested():
            break
        run_dork_scan(target, asset, user_id, control=control)

    return lead_scan


def list_scans_for_target(target_id: int):
    return Scan.query.filter_by(target_id=target_id).order_by(Scan.started_at.desc()).all()
