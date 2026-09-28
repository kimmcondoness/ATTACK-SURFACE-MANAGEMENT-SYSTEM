import csv
import os
import re
from datetime import datetime

from extensions import db
from models import Asset, AuditLog, PortService, Report, Scan, User, Vulnerability
from services.mitigation_service import mitigation_for
from services.report_pdf import SEVERITY_ORDER, build_pdf
from services.risk_service import risk_score, vulnerability_priority

_SEVERITY_RANK = {level: i for i, level in enumerate(SEVERITY_ORDER)}

_STANDARD_NOTES = [
    "Assets are discovered with Subfinder, open ports and services with Nmap, and vulnerabilities with Nuclei, "
    "only against domains the owner has marked as authorized.",
    "CVE entries titled \"Possible CVE-...\" come from searching the NVD database for the service name and version "
    "Nmap detected. That is a keyword match, not a confirmed fix-level match, so each one needs manual verification.",
    "Findings titled \"[Dork]\" are Google dork exposures the scanner confirmed by requesting the file or page on the "
    "host itself and matching its content. Findings titled \"[Config]\" come from the built-in configuration checks "
    "(HTTPS and TLS, security headers, information disclosure, cookies, CORS). Neither kind has a CVE, and exposed "
    "secrets are never copied into the report.",
    "Severity and CVSS scores come from NVD where a CVE is known. Each finding's risk score is its CVSS score "
    "(or, without one, the severity weight: critical 10, high 7, medium 4, low 1), raised for known exploitation. "
    "It is a relative measure, not an absolute one.",
    "Mitigation steps are general guidance for each type of finding. Test changes in a staging environment first.",
]


def _report_filename(target, report_type: str) -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    ext = "pdf" if report_type == "pdf" else "csv"
    safe_domain = target.domain.replace("/", "_")
    return f"{safe_domain}_{timestamp}.{ext}"


def _gather_report_data(target):
    assets = Asset.query.filter_by(target_id=target.id).all()
    asset_ids = [asset.id for asset in assets]
    vulnerabilities = (
        Vulnerability.query.filter(Vulnerability.asset_id.in_(asset_ids)).all()
        if asset_ids
        else []
    )
    return assets, vulnerabilities


def _asset_label(asset):
    return asset.subdomain or asset.url or asset.ip_address or f"asset-{asset.id}"


def _sorted_findings(vulnerabilities):
    return sorted(
        vulnerabilities,
        key=lambda v: (_SEVERITY_RANK.get((v.severity or "").lower(), 99), -(v.cvss_score or 0), v.title or ""),
    )


def _mock_notes(target):
    """Which phases ran on built-in sample data instead of a real tool."""
    mock_phases = sorted(
        {s.scan_type.replace("_", " ") for s in Scan.query.filter_by(target_id=target.id).all() if s.source == "mock"}
    )
    if not mock_phases:
        return []
    return [
        "These phases ran on built-in sample data because the tool was not installed: "
        f"{', '.join(mock_phases)}. Findings from those phases are placeholders, not real results."
    ]


def _build_report_data(target, generated_by: int):
    assets, vulnerabilities = _gather_report_data(target)
    asset_by_id = {a.id: a for a in assets}

    ports_by_asset = {}
    if assets:
        for port in PortService.query.filter(PortService.asset_id.in_(list(asset_by_id))).order_by(PortService.port).all():
            ports_by_asset.setdefault(port.asset_id, []).append(port)

    findings = []
    for v in _sorted_findings(vulnerabilities):
        mitigation = mitigation_for(v)
        findings.append(
            {
                "severity": (v.severity or "medium").lower(),
                "cve": v.cve,
                "cvss": v.cvss_score,
                "risk": vulnerability_priority(v),
                "dork": (v.title or "").lower().startswith("[dork]"),
                "config": (v.title or "").lower().startswith("[config]"),
                "title": v.title,
                "description": (v.description or "")[:500],
                "status": v.status or "open",
                "asset": _asset_label(asset_by_id[v.asset_id]) if v.asset_id in asset_by_id else "",
                "kev": bool(v.kev),
                "exploit": bool(v.exploit_available),
                "keyword_match": bool(v.cve and "possible cve-" in (v.title or "").lower()),
                "steps": mitigation["steps"],
                "timeframe": mitigation["timeframe"],
            }
        )

    counts = {level: 0 for level in SEVERITY_ORDER}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    author = User.query.get(generated_by)
    author_name = (
        " ".join(p for p in (author.first_name, author.last_name) if p) or author.username if author else None
    )

    return {
        "domain": target.domain,
        "generated_at": datetime.utcnow(),
        "generated_by": author_name,
        "counts": counts,
        "risk_score": risk_score(target.id),
        "port_total": sum(len(p) for p in ports_by_asset.values()),
        "assets": [
            {
                "label": _asset_label(a),
                "ip": a.ip_address,
                "ports": ", ".join(f"{p.port}/{p.service_name or '?'}" for p in ports_by_asset.get(a.id, [])),
            }
            for a in assets
        ],
        "findings": findings,
        "notes": _mock_notes(target) + _STANDARD_NOTES,
    }


def _save_report(target, report_type, file_path, generated_by):
    report = Report(target_id=target.id, report_type=report_type, file_path=file_path, generated_by=generated_by)
    db.session.add(report)
    db.session.commit()
    return report


def generate_csv_report(target, reports_dir: str, generated_by: int) -> Report:
    data = _build_report_data(target, generated_by)
    file_path = os.path.join(reports_dir, _report_filename(target, "csv"))

    os.makedirs(reports_dir, exist_ok=True)
    with open(file_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Asset", "Severity", "CVE", "Title", "Status", "CVSS", "Risk score", "Mitigation", "Suggested timeframe"])
        if not data["findings"]:
            writer.writerow([data["domain"], "-", "-", "No findings", "-", "-", "-", "-", "-"])
        for f in data["findings"]:
            writer.writerow(
                [
                    f["asset"],
                    f["severity"],
                    f["cve"] or "-",
                    f["title"],
                    f["status"],
                    f["cvss"] if f["cvss"] is not None else "-",
                    f["risk"],
                    " | ".join(f"{n}. {step}" for n, step in enumerate(f["steps"], start=1)),
                    f["timeframe"],
                ]
            )

    return _save_report(target, "csv", file_path, generated_by)


def generate_pdf_report(target, reports_dir: str, generated_by: int) -> Report:
    data = _build_report_data(target, generated_by)
    file_path = os.path.join(reports_dir, _report_filename(target, "pdf"))

    os.makedirs(reports_dir, exist_ok=True)
    build_pdf(file_path, data)

    return _save_report(target, "pdf", file_path, generated_by)


def opened_report_ids(user_id: int) -> set:
    """Reports this user has downloaded from the history list, read back from
    the audit log entries written by the download route."""
    rows = AuditLog.query.filter_by(user_id=user_id, action="report_downloaded").with_entities(AuditLog.detail).all()
    matches = (re.fullmatch(r"report_id=(\d+)", detail or "") for (detail,) in rows)
    return {int(m.group(1)) for m in matches if m}


def list_reports_for_target(target_id: int):
    return Report.query.filter_by(target_id=target_id).order_by(Report.generated_at.desc()).all()
