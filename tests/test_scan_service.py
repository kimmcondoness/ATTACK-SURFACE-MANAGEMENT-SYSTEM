import pytest

from services import scan_service, target_service
from services.scan_service import UnauthorizedTargetError


def test_run_asset_discovery_rejects_unauthorized_target(app, analyst_user):
    target = target_service.create_target(
        owner_id=analyst_user.id, domain="unauth.example.com", authorized=False
    )
    with pytest.raises(UnauthorizedTargetError):
        scan_service.run_asset_discovery(target, analyst_user.id)


def test_run_asset_discovery_succeeds_with_mock_data(app, analyst_user):
    target = target_service.create_target(
        owner_id=analyst_user.id, domain="authorized.example.com", authorized=True
    )
    scan = scan_service.run_asset_discovery(target, analyst_user.id)

    assert scan.status == "completed"
    assert scan.source == "mock"

    from services.asset_service import list_assets_for_target

    assets = list_assets_for_target(target.id)
    assert len(assets) > 0


def test_full_mock_workflow_creates_vulnerabilities(app, analyst_user):
    target = target_service.create_target(
        owner_id=analyst_user.id, domain="fullflow.example.com", authorized=True
    )
    scan_service.run_asset_discovery(target, analyst_user.id)

    from services.asset_service import list_assets_for_target

    asset = list_assets_for_target(target.id)[0]

    scan_service.run_port_discovery(target, asset, analyst_user.id)
    scan_service.run_vulnerability_scan(target, asset, analyst_user.id)

    from services.risk_service import dashboard_summary

    summary = dashboard_summary()
    assert summary["total_vulnerabilities"] > 0
