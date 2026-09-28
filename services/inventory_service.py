"""Row builders for the per-inventory pages (Domains, Subdomains, IP
Addresses, Web Applications, Open Ports, Public Services).

Each page is a plain table, so every builder returns (columns, rows) where
a row is a list of cell dicts: {"text", "kind", "href"?, "pill"?}. That
keeps the six pages on one template instead of six near-identical ones.
"""

from collections import defaultdict

from models import AuthorizedTarget, PortService
from services.risk_service import risk_score

# slug -> page metadata. `group` matches the sidebar section it lives under.
PAGES = {
    "domains": {
        "title": "Domains",
        "group": "Recon",
        "blurb": "Every root domain you have authorized, with what has been found under each.",
        "empty": "No domains yet. Run a scan from the Dashboard to add one.",
    },
    "subdomains": {
        "title": "Subdomains",
        "group": "Recon",
        "blurb": "Hostnames found by Subfinder, plus each scanned root host.",
        "empty": "No subdomains recorded yet. Run asset discovery on a target.",
    },
    "ip-addresses": {
        "title": "IP Addresses",
        "group": "Recon",
        "blurb": "Assets with a recorded IP address.",
        "empty": "No IP addresses recorded yet. Subfinder returns hostnames only, "
        "so nothing here has been resolved to an IP.",
    },
    "web-applications": {
        "title": "Web Applications",
        "group": "Web",
        "blurb": "Assets reachable over HTTP(S), with the findings attached to each.",
        "empty": "No web applications recorded yet. Run a scan to discover some.",
    },
    "open-ports": {
        "title": "Open Ports",
        "group": "Network",
        "blurb": "Every open port Nmap reported, by asset.",
        "empty": "No open ports recorded yet. Port discovery runs after asset discovery.",
    },
    "public-services": {
        "title": "Public Services",
        "group": "Network",
        "blurb": "Open ports grouped by the service Nmap identified on them.",
        "empty": "No services identified yet. Run port discovery on a target.",
    },
}


def owned_targets(owner_id: int):
    return AuthorizedTarget.query.filter_by(owner_id=owner_id).order_by(AuthorizedTarget.created_at.desc()).all()


def _ports_by_asset(assets):
    ids = [a.id for a in assets]
    grouped = defaultdict(list)
    if ids:
        for port in PortService.query.filter(PortService.asset_id.in_(ids)).order_by(PortService.port).all():
            grouped[port.asset_id].append(port)
    return grouped


def nav_counts(targets):
    """Sidebar badges. Always computed over every target, never the
    filtered view, so the counts describe the whole inventory."""
    assets = [a for t in targets for a in t.assets]
    ports = [p for plist in _ports_by_asset(assets).values() for p in plist]
    return {
        "domains": len(targets),
        "subdomains": sum(1 for a in assets if a.subdomain),
        "ips": sum(1 for a in assets if a.ip_address),
        "webapps": sum(1 for a in assets if a.url),
        "ports": len(ports),
        "services": len({p.service_name for p in ports if p.service_name}),
    }


def _text(value):
    return {"text": value if value not in (None, "") else "-", "kind": "text"}


def _mono(value):
    return {"text": value if value not in (None, "") else "-", "kind": "mono"}


def _date(value):
    return _mono(value.strftime("%Y-%m-%d") if value else None)


def _pill(text, pill):
    return {"text": text, "kind": "pill", "pill": pill}


def _asset_label(asset):
    return asset.subdomain or asset.url or asset.ip_address or f"asset-{asset.id}"


def _domains(targets):
    rows = []
    for t in targets:
        ports = _ports_by_asset(t.assets)
        rows.append(
            [
                _mono(t.domain),
                _pill("Authorized", "active") if t.authorized else _pill("Pending", "inactive"),
                _mono(sum(1 for a in t.assets if a.subdomain)),
                _mono(sum(1 for a in t.assets if a.url)),
                _mono(sum(len(p) for p in ports.values())),
                _mono(sum(len(a.vulnerabilities) for a in t.assets)),
                _mono(risk_score(t.id)),
                _date(t.created_at),
            ]
        )
    columns = ["Domain", "Authorized", "Subdomains", "Web apps", "Open ports", "Findings", "Risk", "Added"]
    return columns, rows


def _subdomains(targets):
    rows = []
    for t in targets:
        for a in t.assets:
            if a.subdomain:
                rows.append([_mono(a.subdomain), _mono(t.domain), _mono(a.ip_address), _date(a.discovery_date)])
    return ["Subdomain", "Target", "IP address", "Discovered"], rows


def _ip_addresses(targets):
    rows = []
    for t in targets:
        ports = _ports_by_asset(t.assets)
        for a in t.assets:
            if a.ip_address:
                rows.append(
                    [
                        _mono(a.ip_address),
                        _mono(a.subdomain),
                        _mono(t.domain),
                        _mono(len(ports.get(a.id, []))),
                        _date(a.discovery_date),
                    ]
                )
    return ["IP address", "Hostname", "Target", "Open ports", "Discovered"], rows


def _web_applications(targets):
    rows = []
    for t in targets:
        ports = _ports_by_asset(t.assets)
        for a in t.assets:
            if not a.url:
                continue
            link = {"text": a.url, "kind": "link"}
            if a.url.lower().startswith(("http://", "https://")):
                link["href"] = a.url
            rows.append(
                [
                    link,
                    _mono(t.domain),
                    _mono(len(ports.get(a.id, []))),
                    _mono(len(a.vulnerabilities)),
                    _date(a.discovery_date),
                ]
            )
    return ["URL", "Target", "Open ports", "Findings", "Discovered"], rows


def _open_ports(targets):
    rows = []
    for t in targets:
        ports = _ports_by_asset(t.assets)
        for a in t.assets:
            for p in ports.get(a.id, []):
                rows.append(
                    [
                        _mono(_asset_label(a)),
                        _mono(p.port),
                        _mono(p.protocol),
                        _text(p.service_name),
                        _mono(p.service_version),
                        _pill("Open", "active") if p.state == "open" else _pill(p.state, "inactive"),
                        _mono(t.domain),
                    ]
                )
    return ["Asset", "Port", "Protocol", "Service", "Version", "State", "Target"], rows


def _public_services(targets):
    assets = [a for t in targets for a in t.assets]
    by_service = defaultdict(lambda: {"ports": set(), "hosts": set(), "versions": set()})
    for asset_id, plist in _ports_by_asset(assets).items():
        for p in plist:
            if not p.service_name:
                continue
            entry = by_service[p.service_name]
            entry["ports"].add(p.port)
            entry["hosts"].add(asset_id)
            if p.service_version:
                entry["versions"].add(p.service_version)
    rows = []
    for name, entry in sorted(by_service.items(), key=lambda kv: (-len(kv[1]["hosts"]), kv[0])):
        rows.append(
            [
                _text(name),
                _mono(", ".join(str(p) for p in sorted(entry["ports"]))),
                _mono(len(entry["hosts"])),
                _mono(", ".join(sorted(entry["versions"]))),
            ]
        )
    return ["Service", "Ports", "Hosts", "Versions seen"], rows


_BUILDERS = {
    "domains": _domains,
    "subdomains": _subdomains,
    "ip-addresses": _ip_addresses,
    "web-applications": _web_applications,
    "open-ports": _open_ports,
    "public-services": _public_services,
}


def build_page(slug: str, targets):
    """Return (columns, rows) for `slug` over `targets`."""
    return _BUILDERS[slug](targets)
