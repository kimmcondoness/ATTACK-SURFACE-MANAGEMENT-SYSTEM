from urllib.parse import urlparse

from scanner.base import ScannerResult, ScanControl
from scanner.exposure_scanner import CHECKS, ExposureScanner, Response, bucket_names
from services import scan_service, target_service
from services.asset_service import get_or_create_self_asset
from services.dork_service import exposed_dork_labels, query_for
from services.mitigation_service import mitigation_for
from services.risk_service import vulnerability_priority
from models import SEVERITIES, Vulnerability

HOST = "shop.example.com"
HTML_HOME = b"<!doctype html><html><body>Welcome</body></html>"


def fake_web(routes, home=HTML_HOME):
    """A fetch function backed by a {path: (status, headers, body)} dict.
    Unknown paths answer 404, "/" answers the home page."""
    table = {"/": (200, {"content-type": "text/html"}, home)}
    table.update(routes)

    def fetch(url):
        path = urlparse(url).path
        if path.startswith("/asm-check-") and path not in table:
            path = "<nonce>"
        status, headers, body = table.get(path, table.get("<nonce>", (404, {}, b"Not Found")))
        return Response(url, status, headers, body)

    return fetch


def scan(routes, **kwargs):
    return ExposureScanner(fetch=fake_web(routes, kwargs.pop("home", HTML_HOME))).run(HOST, **kwargs)


def titles(result):
    return [f["title"] for f in result.data]


def test_confirmed_env_file_becomes_a_critical_finding_without_leaking_values():
    secret = "hunter2-very-secret"
    body = f"APP_KEY=base64:abc\nDB_PASSWORD={secret}\nDB_HOST=10.0.0.5\n".encode()
    result = scan({"/.env": (200, {"content-type": "text/plain"}, body)})

    assert result.success and result.source == "real"
    assert titles(result) == ["[Dork] Exposed environment file: /.env"]
    finding = result.data[0]
    assert finding["severity"] == "critical" and finding["cve"] is None
    assert "DB_PASSWORD" in finding["description"]
    assert secret not in finding["description"] + finding["recommendation"]
    assert finding["description"].startswith('Google dork "Laravel .env files"')


def test_html_page_at_a_secret_path_is_not_a_finding():
    spa = {p: (200, {"content-type": "text/html"}, HTML_HOME) for p in ("/.env", "/.git/config", "/backup.zip")}
    assert scan(spa).data == []


def test_catch_all_site_that_answers_everything_with_200_reports_nothing():
    everything = b"APP_KEY=x\nDB_PASSWORD=y\n"  # even a valid-looking body
    routes = {"/.env": (200, {}, everything), "<nonce>": (200, {}, everything)}
    assert scan(routes).data == []


def test_git_config_is_detected():
    result = scan({"/.git/config": (200, {"content-type": "text/plain"}, b"[core]\n\trepositoryformatversion = 0\n")})
    assert titles(result) == ["[Dork] Exposed .git repository: /.git/config"]
    assert result.data[0]["severity"] == "high"


def test_backup_archive_is_matched_by_file_header_not_downloaded():
    zip_bytes = b"PK\x03\x04" + b"\x00" * 50
    result = scan({
        "/backup.zip": (200, {"content-type": "application/zip"}, zip_bytes),
        "/site.zip": (200, {"content-type": "text/html"}, zip_bytes),
    })
    assert titles(result) == ["[Dork] Downloadable backup archive: /backup.zip"]


def test_debug_page_on_the_error_route_is_detected_once_with_no_path_suffix():
    page = b"<html>You're seeing this error because you have DEBUG = True in your Django settings</html>"
    result = scan({"<nonce>": (404, {"content-type": "text/html"}, page)})
    assert titles(result) == ["[Dork] Django running with DEBUG enabled"]


def test_unreachable_host_is_a_clean_skip_not_a_failure():
    result = ExposureScanner(fetch=lambda url: None).run(HOST)
    assert result.success and result.data == [] and result.raw_output == "unreachable"


def test_https_asset_url_falls_back_to_http_when_the_site_is_http_only():
    plain = fake_web({"/.env": (200, {"content-type": "text/plain"}, b"APP_KEY=a\nDB_HOST=b\n")})

    def http_only(url):
        return plain(url) if url.startswith("http://") else None

    result = ExposureScanner(fetch=http_only).run(f"https://{HOST}")
    assert titles(result) == ["[Dork] Exposed environment file: /.env"]
    assert result.data[0]["description"].count("http://") == 1


def test_stop_request_aborts_the_scan():
    control = ScanControl()
    control.request_stop()
    result = ExposureScanner(fetch=fake_web({})).run(HOST, control=control)
    assert result.stopped and result.data == []


def test_public_bucket_is_only_checked_when_a_bucket_domain_is_given():
    listing = b"<?xml version='1.0'?><ListBucketResult><Name>example.com</Name></ListBucketResult>"

    def fetch(url):
        if url == "https://s3.amazonaws.com/example.com/":
            return Response(url, 200, {"content-type": "application/xml"}, listing)
        return fake_web({})(url)

    scanner = ExposureScanner(fetch=fetch)
    assert scanner.run(HOST).data == []
    result = scanner.run(HOST, bucket_domain="example.com")
    assert titles(result) == ["[Dork] Publicly listable Amazon S3 bucket: example.com"]
    assert result.data[0]["severity"] == "critical"
    assert bucket_names("www.example.com") == ["example.com", "example-com"]


def test_every_check_maps_to_a_real_dork_and_uses_a_valid_severity():
    for check in CHECKS:
        assert query_for(check.label, HOST), check.key
        assert check.severity in SEVERITIES, check.key
        assert check.steps and check.impact, check.key


def _stub_scanner(monkeypatch, result):
    class Stub:
        def run(self, host, control=None, bucket_domain=None):
            return result

    monkeypatch.setattr(scan_service, "ExposureScanner", Stub)


def _asset(analyst_user, domain="shop.example.com"):
    target = target_service.create_target(owner_id=analyst_user.id, domain=domain, authorized=True)
    return target, get_or_create_self_asset(target)


def test_dork_scan_stores_findings_with_mitigation_and_a_risk_score(app, analyst_user, monkeypatch):
    finding = {
        "severity": "critical", "cve": None, "title": "[Dork] Exposed environment file: /.env",
        "description": 'Google dork "Laravel .env files": site:x. Confirmed by requesting https://x/.env.',
        "recommendation": "Delete the file.\nRotate every credential.",
    }
    _stub_scanner(monkeypatch, ScannerResult(success=True, source="real", data=[finding], raw_output="114 requests"))
    target, asset = _asset(analyst_user)

    scan = scan_service.run_dork_scan(target, asset, analyst_user.id)
    assert scan.scan_type == "dork_scan" and scan.status == "completed" and scan.source == "real"
    assert "1 exposure(s) confirmed" in scan.result_summary

    vuln = Vulnerability.query.filter_by(asset_id=asset.id).one()
    assert vulnerability_priority(vuln) == 10.0
    mitigation = mitigation_for(vuln)
    assert mitigation["steps"][:2] == ["Delete the file.", "Rotate every credential."]
    assert mitigation["steps"][-1].startswith("Re-run the scan")
    assert "24 to 72 hours" in mitigation["timeframe"]
    assert exposed_dork_labels(target.id) == {"Laravel .env files": 1}


def test_rescanning_does_not_duplicate_a_recorded_exposure(app, analyst_user, monkeypatch):
    finding = {"severity": "high", "cve": None, "title": "[Dork] Exposed .git repository: /.git/config",
               "description": 'Google dork "Exposed .git repository": q.', "recommendation": "Remove it."}
    _stub_scanner(monkeypatch, ScannerResult(success=True, source="real", data=[finding], raw_output="114 requests"))
    target, asset = _asset(analyst_user)

    scan_service.run_dork_scan(target, asset, analyst_user.id)
    second = scan_service.run_dork_scan(target, asset, analyst_user.id)

    assert Vulnerability.query.filter_by(asset_id=asset.id).count() == 1
    assert "1 already recorded" in second.result_summary


def test_dork_scan_on_an_unreachable_host_completes_with_a_note(app, analyst_user, monkeypatch):
    _stub_scanner(monkeypatch, ScannerResult(success=True, source="real", raw_output="unreachable"))
    target, asset = _asset(analyst_user)
    scan = scan_service.run_dork_scan(target, asset, analyst_user.id)
    assert scan.status == "completed" and "skipped" in scan.result_summary


def test_report_includes_risk_score_and_dork_marker(app, analyst_user, monkeypatch, tmp_path):
    import csv

    from services import report_service

    finding = {"severity": "high", "cve": None, "title": "[Dork] Exposed .git repository: /.git/config",
               "description": 'Google dork "Exposed .git repository": q.', "recommendation": "Remove it."}
    _stub_scanner(monkeypatch, ScannerResult(success=True, source="real", data=[finding], raw_output="114 requests"))
    target, asset = _asset(analyst_user)
    scan_service.run_dork_scan(target, asset, analyst_user.id)

    data = report_service._build_report_data(target, analyst_user.id)
    assert data["findings"][0]["risk"] == 7.0 and data["findings"][0]["dork"] is True

    report = report_service.generate_csv_report(target, str(tmp_path), analyst_user.id)
    with open(report.file_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["Risk score"] == "7.0" and "Remove it." in rows[0]["Mitigation"]

    pdf = report_service.generate_pdf_report(target, str(tmp_path), analyst_user.id)
    assert open(pdf.file_path, "rb").read(5) == b"%PDF-"
