from datetime import datetime

from extensions import db
from models import Asset, PortService


def store_discovered_assets(target_id: int, discovered):
    """discovered: list of {"subdomain": ..., "url": ...}"""
    created = []
    for item in discovered:
        asset = Asset(
            target_id=target_id,
            subdomain=item.get("subdomain"),
            url=item.get("url"),
        )
        db.session.add(asset)
        created.append(asset)
    db.session.commit()
    return created


def store_ports_for_asset(asset_id: int, ports):
    """ports: list of {"port", "protocol", "state", "service_name", "service_version"}"""
    created = []
    for item in ports:
        port_service = PortService(
            asset_id=asset_id,
            port=item["port"],
            protocol=item.get("protocol", "tcp"),
            service_name=item.get("service_name"),
            service_version=item.get("service_version"),
            state=item.get("state", "open"),
        )
        db.session.add(port_service)
        created.append(port_service)
    db.session.commit()
    return created


def get_or_create_self_asset(target):
    """Ensure the target's own host has an Asset row, so port/vulnerability
    scanning has something to point at even when subdomain enumeration
    finds nothing (e.g. the submitted host is already a leaf subdomain).
    """
    now = datetime.utcnow()
    existing = Asset.query.filter_by(target_id=target.id, subdomain=target.domain).first()
    if existing:
        existing.last_seen_at = now
        existing.status = "active"
        db.session.commit()
        return existing
    asset = Asset(target_id=target.id, subdomain=target.domain, url=f"https://{target.domain}", last_seen_at=now, status="active")
    db.session.add(asset)
    db.session.commit()
    return asset


def record_asset_ip(asset, ip_address):
    """Store the IP a real port scan resolved the asset to (latest wins,
    since DNS answers change)."""
    if ip_address and asset.ip_address != ip_address:
        asset.ip_address = ip_address
        db.session.commit()


def list_assets_for_target(target_id: int):
    return Asset.query.filter_by(target_id=target_id).all()


def get_asset(asset_id: int):
    return Asset.query.get(asset_id)
