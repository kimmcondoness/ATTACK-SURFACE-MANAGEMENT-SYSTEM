import csv
from types import SimpleNamespace

from extensions import db
from models import Asset, Vulnerability
from services import report_service, target_service
from services.mitigation_service import mitigation_for


def _vuln(**kw):
    base = dict(title="", cve=None, severity="medium", recommendation="", kev=False, exploit_available=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_missing_headers_gets_header_specific_steps():
    steps = mitigation_for(_vuln(title="Missing security headers"))["steps"]
    assert any("Content-Security-Policy" in s for s in steps)


def test_keyword_matched_cve_is_not_mistaken_for_a_tls_finding():
    # the banner "ssl|https" contains "ssl", which the TLS title rule would grab
    v = _vuln(title="Possible CVE-2020-1234 affecting ssl|https (port 443)", cve="CVE-2020-1234")
    steps = mitigation_for(v)["steps"]
    assert any("NVD entry for CVE-2020-1234" in s for s in steps)
    assert not any("TLS 1.0" in s for s in steps)


def test_cdn_banner_match_warns_it_may_not_be_the_origin():
    v = _vuln(title="Possible CVE-2023-2512 affecting http cloudflare (port 80)", cve="CVE-2023-2512")
    assert "CDN or proxy edge" in mitigation_for(v)["steps"][0]


def test_non_cdn_cve_asks_to_confirm_the_version_first():
    v = _vuln(title="Possible CVE-2021-41773 affecting Apache 2.4.49 (port 80)", cve="CVE-2021-41773")
    assert mitigation_for(v)["steps"][0].startswith("Confirm the exact software")


def test_kev_finding_is_marked_immediate_whatever_its_severity():
    assert mitigation_for(_vuln(severity="low", kev=True))["timeframe"].startswith("Immediately")


def test_timeframe_follows_severity():
    assert "7 days" in mitigation_for(_vuln(severity="high"))["timeframe"]
    assert "30 days" in mitigation_for(_vuln(severity="medium"))["timeframe"]


def test_stored_recommendation_is_used_but_the_nvd_boilerplate_is_not():
    own = mitigation_for(_vuln(title="Odd thing", recommendation="Rotate the shared key."))["steps"]
    assert own[0] == "Rotate the shared key."
    boiler = mitigation_for(
        _vuln(title="Odd thing", recommendation="Matched via an NVD keyword search on the detected banner")
    )["steps"]
    assert not boiler[0].startswith("Matched via")


def _target_with_findings(analyst_user):
    target = target_service.create_target(owner_id=analyst_user.id, domain="rep.example.com", authorized=True)
    asset = Asset(target_id=target.id, subdomain="www.rep.example.com")
    db.session.add(asset)
    db.session.commit()
    db.session.add_all(
        [
            Vulnerability(asset_id=asset.id, severity="low", title="Server version disclosure", description="x"),
            Vulnerability(
                asset_id=asset.id,
                severity="critical",
                cve="CVE-2021-44228",
                title="Possible CVE-2021-44228 affecting java (port 8080)",
                cvss_score=10.0,
                kev=True,
            ),
        ]
    )
    db.session.commit()
    return target


def test_pdf_report_is_a_real_pdf_and_is_recorded(app, analyst_user, tmp_path):
    target = _target_with_findings(analyst_user)
    report = report_service.generate_pdf_report(target, str(tmp_path), analyst_user.id)

    with open(report.file_path, "rb") as fh:
        assert fh.read(5) == b"%PDF-"
    assert report.report_type == "pdf" and report.id is not None


def test_pdf_report_builds_with_no_findings(app, analyst_user, tmp_path):
    target = target_service.create_target(owner_id=analyst_user.id, domain="empty.example.com", authorized=True)
    report = report_service.generate_pdf_report(target, str(tmp_path), analyst_user.id)
    with open(report.file_path, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_csv_report_carries_mitigation_and_sorts_worst_first(app, analyst_user, tmp_path):
    target = _target_with_findings(analyst_user)
    report = report_service.generate_csv_report(target, str(tmp_path), analyst_user.id)

    with open(report.file_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["Severity"] == "critical"
    assert rows[0]["Suggested timeframe"].startswith("Immediately")
    assert "1. " in rows[0]["Mitigation"]
    assert rows[1]["Severity"] == "low"
