import pytest

from services import scan_service, target_service
from services.scan_service import UnauthorizedTargetError


def test_run_asset_discovery_rejects_unauthorized_target(app, analyst_user):
    target = target_service.create_target(
        owner_id=analyst_user.id, domain="unauth.example.com", authorized=False
    )
    with pytest.raises(UnauthorizedTargetError):
        scan_service.run_asset_discovery(target, analyst_user.id)


@pytest.fixture
def no_scanner_tools(monkeypatch):
    """Behave as on a machine with none of the scanner tools installed, whatever is really
    installed, and never reach the NVD, so these tests give the same answer everywhere."""
    from scanner.base import BaseScanner

    monkeypatch.setattr(BaseScanner, "is_available", lambda self: False)
    monkeypatch.setattr(scan_service, "lookup_cves_for_query", lambda query: [])


def test_run_asset_discovery_succeeds_with_mock_data(app, analyst_user, no_scanner_tools):
    target = target_service.create_target(
        owner_id=analyst_user.id, domain="authorized.example.com", authorized=True
    )
    scan = scan_service.run_asset_discovery(target, analyst_user.id)

    assert scan.status == "completed"
    assert scan.source == "mock"

    from services.asset_service import list_assets_for_target

    assets = list_assets_for_target(target.id)
    assert len(assets) > 0


def test_vulnerability_scan_without_nuclei_runs_the_builtin_checks_and_invents_nothing(app, analyst_user, no_scanner_tools, monkeypatch):
    class Stub:
        def run(self, host, control=None):
            from scanner.base import ScannerResult

            finding = {"severity": "medium", "cve": None, "title": "[Config] Missing security header: Content-Security-Policy",
                       "description": "d", "recommendation": "Add it.\nRe-run."}
            return ScannerResult(success=True, source="real", data=[finding], raw_output="checked")

    monkeypatch.setattr(scan_service, "ConfigScanner", Stub)
    target = target_service.create_target(owner_id=analyst_user.id, domain="fullflow.example.com", authorized=True)
    scan_service.run_asset_discovery(target, analyst_user.id)

    from services.asset_service import list_assets_for_target
    from models import Vulnerability

    asset = list_assets_for_target(target.id)[0]
    scan_service.run_port_discovery(target, asset, analyst_user.id)
    scan = scan_service.run_vulnerability_scan(target, asset, analyst_user.id)

    assert scan.status == "completed" and scan.source == "real"
    assert "Nuclei is not installed" in scan.result_summary
    titles = [v.title for v in Vulnerability.query.filter_by(asset_id=asset.id).all()]
    assert titles == ["[Config] Missing security header: Content-Security-Policy"]   # the old made-up findings are gone

    from services.risk_service import dashboard_summary

    assert dashboard_summary()["total_vulnerabilities"] == 1


_NMAP_OUTPUT = (
    "# Nmap 7.80 scan initiated\n"
    "Host: 54.73.53.134 (ec2-54-73-53-134.eu-west-1.compute.amazonaws.com)\tStatus: Up\n"
    "Host: 54.73.53.134 (ec2-54-73-53-134.eu-west-1.compute.amazonaws.com)\t"
    "Ports: 80/open/tcp//http//heroku-router/, 443/open/tcp//ssl|https//heroku-router/\n"
)


def test_extract_host_ip_reads_the_address_not_the_hostname():
    from scanner.nmap_scanner import NmapScanner

    assert NmapScanner.extract_host_ip(_NMAP_OUTPUT) == "54.73.53.134"
    assert NmapScanner.extract_host_ip("Host: not-an-ip ()\tStatus: Up\n") is None
    assert NmapScanner.extract_host_ip("") is None
    assert NmapScanner.extract_host_ip(None) is None


def test_real_port_scan_records_the_resolved_ip(app, analyst_user, monkeypatch):
    from scanner.base import ScannerResult
    from scanner.nmap_scanner import NmapScanner
    from services.asset_service import get_or_create_self_asset

    target = target_service.create_target(
        owner_id=analyst_user.id, domain="iprecord.example.com", authorized=True
    )
    asset = get_or_create_self_asset(target)
    scanner = NmapScanner()
    monkeypatch.setattr(
        NmapScanner,
        "run",
        lambda self, host, control=None: ScannerResult(
            success=True, source="real", data=scanner.parse_output(_NMAP_OUTPUT, host), raw_output=_NMAP_OUTPUT
        ),
    )

    scan_service.run_port_discovery(target, asset, analyst_user.id)

    assert asset.ip_address == "54.73.53.134"


def test_mock_port_scan_never_invents_an_ip(app, analyst_user, monkeypatch):
    from scanner.nmap_scanner import NmapScanner
    from services.asset_service import get_or_create_self_asset

    target = target_service.create_target(
        owner_id=analyst_user.id, domain="noip.example.com", authorized=True
    )
    asset = get_or_create_self_asset(target)
    monkeypatch.setattr(NmapScanner, "is_available", lambda self: False)

    scan_service.run_port_discovery(target, asset, analyst_user.id)

    assert asset.ip_address is None


def test_port_scan_targets_the_hostname_even_after_an_ip_is_stored(app, analyst_user, monkeypatch):
    from scanner.base import ScannerResult
    from scanner.nmap_scanner import NmapScanner
    from services.asset_service import get_or_create_self_asset

    target = target_service.create_target(
        owner_id=analyst_user.id, domain="vhost.example.com", authorized=True
    )
    asset = get_or_create_self_asset(target)
    asset.ip_address = "203.0.113.9"
    seen = []

    def fake_run(self, host, control=None):
        seen.append(host)
        return ScannerResult(success=True, source="real", data=[], raw_output="")

    monkeypatch.setattr(NmapScanner, "run", fake_run)
    scan_service.run_port_discovery(target, asset, analyst_user.id)

    assert seen == ["vhost.example.com"]
