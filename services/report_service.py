import csv
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

from extensions import db
from models import Asset, Report, Vulnerability
from services.risk_service import risk_score, severity_counts


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


def generate_csv_report(target, reports_dir: str, generated_by: int) -> Report:
    assets, vulnerabilities = _gather_report_data(target)
    filename = _report_filename(target, "csv")
    file_path = os.path.join(reports_dir, filename)

    os.makedirs(reports_dir, exist_ok=True)
    with open(file_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Asset", "Severity", "CVE", "Title", "Status"])
        vulns_by_asset = {}
        for vuln in vulnerabilities:
            vulns_by_asset.setdefault(vuln.asset_id, []).append(vuln)
        for asset in assets:
            asset_label = asset.subdomain or asset.url or asset.ip_address or f"asset-{asset.id}"
            asset_vulns = vulns_by_asset.get(asset.id, [])
            if not asset_vulns:
                writer.writerow([asset_label, "-", "-", "No findings", "-"])
                continue
            for vuln in asset_vulns:
                writer.writerow([asset_label, vuln.severity, vuln.cve or "-", vuln.title, vuln.status])

    report = Report(
        target_id=target.id, report_type="csv", file_path=file_path, generated_by=generated_by
    )
    db.session.add(report)
    db.session.commit()
    return report


def generate_pdf_report(target, reports_dir: str, generated_by: int) -> Report:
    assets, vulnerabilities = _gather_report_data(target)
    filename = _report_filename(target, "pdf")
    file_path = os.path.join(reports_dir, filename)

    os.makedirs(reports_dir, exist_ok=True)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(file_path, pagesize=A4)
    story = [
        Paragraph(f"Attack Surface Report - {target.domain}", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {datetime.utcnow().isoformat()} UTC", styles["Normal"]),
        Paragraph(f"Assets discovered: {len(assets)}", styles["Normal"]),
        Paragraph(f"Total findings: {len(vulnerabilities)}", styles["Normal"]),
        Paragraph(f"Risk score: {risk_score(target.id)}", styles["Normal"]),
        Spacer(1, 12),
    ]

    counts = severity_counts(target.id)
    summary_table_data = [["Severity", "Count"]] + [
        [severity.capitalize(), str(count)] for severity, count in counts.items()
    ]
    summary_table = Table(summary_table_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    if vulnerabilities:
        findings_data = [["Severity", "CVE", "Title", "Status"]] + [
            [vuln.severity, vuln.cve or "-", vuln.title, vuln.status] for vuln in vulnerabilities
        ]
        findings_table = Table(findings_data, repeatRows=1)
        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(findings_table)

    doc.build(story)

    report = Report(
        target_id=target.id, report_type="pdf", file_path=file_path, generated_by=generated_by
    )
    db.session.add(report)
    db.session.commit()
    return report


def list_reports_for_target(target_id: int):
    return Report.query.filter_by(target_id=target_id).order_by(Report.generated_at.desc()).all()
