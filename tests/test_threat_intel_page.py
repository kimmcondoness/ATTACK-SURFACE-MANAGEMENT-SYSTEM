import re
import urllib.error

import pytest

import routes.threat_intel as threat_intel
from extensions import db
from models import ROLE_THREAT_INTEL, Asset, AuthorizedTarget, User, Vulnerability
from services import epss_service
from tests.conftest import login


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    epss_service.clear_cache()
    monkeypatch.setattr(threat_intel, "recent_kev_entries", lambda limit=10: [])
    yield
    epss_service.clear_cache()


def _epss_api(scores, calls=None):
    """A stand-in for the FIRST.org endpoint: scores = {cve: (epss, percentile)}."""

    def fetch(url):
        if calls is not None:
            calls.append(url)
        asked = re.search(r"cve=([^&]+)", url).group(1).replace("%2C", ",").split(",")
        return {"status": "OK", "data": [{"cve": c, "epss": str(scores[c][0]), "percentile": str(scores[c][1]), "date": "2026-09-28"} for c in asked if c in scores]}

    return fetch


# ------------------------------------------------------------------ epss_service
def test_cve_ids_splits_dedupes_and_ignores_junk():
    assert epss_service.cve_ids("CVE-2021-44228,cve-2021-44228, CVE-2023-2512") == ["CVE-2021-44228", "CVE-2023-2512"]
    assert epss_service.cve_ids("not a cve; CVE-99-1; ") == []
    assert epss_service.cve_ids(None) == []


def test_lookup_returns_scores_and_batches_one_request(monkeypatch):
    calls = []
    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({"CVE-2021-44228": (0.945, 0.999), "CVE-2023-2512": (0.004, 0.31)}, calls))

    scores = epss_service.lookup(["CVE-2021-44228", "CVE-2023-2512", "CVE-2021-44228"])

    assert scores == {"CVE-2021-44228": {"epss": 0.945, "percentile": 0.999}, "CVE-2023-2512": {"epss": 0.004, "percentile": 0.31}}
    assert len(calls) == 1 and "CVE-2021-44228,CVE-2023-2512" in calls[0]


def test_lookup_caches_scores_and_the_absence_of_a_score(monkeypatch):
    calls = []
    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({"CVE-2021-44228": (0.9, 0.99)}, calls))

    epss_service.lookup(["CVE-2021-44228", "CVE-2020-0001"])   # the second one has no published score
    again = epss_service.lookup(["CVE-2021-44228", "CVE-2020-0001"])

    assert len(calls) == 1 and list(again) == ["CVE-2021-44228"]


def test_lookup_survives_an_unreachable_api_and_does_not_cache_the_failure(monkeypatch):
    def down(url):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(epss_service, "_fetch_json", down)
    assert epss_service.lookup(["CVE-2021-44228"]) == {}

    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({"CVE-2021-44228": (0.9, 0.99)}))
    assert "CVE-2021-44228" in epss_service.lookup(["CVE-2021-44228"])   # tried again once the API was back


def test_lookup_skips_ids_that_are_not_cves(monkeypatch):
    calls = []
    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({}, calls))
    assert epss_service.lookup(["", "x'; drop table", "CVE-1-2"]) == {} and calls == []


def test_best_score_takes_the_highest_epss_of_several_cves():
    scores = {"CVE-2021-1111": {"epss": 0.02, "percentile": 0.4}, "CVE-2021-2222": {"epss": 0.7, "percentile": 0.98}}
    assert epss_service.best_score("CVE-2021-1111,CVE-2021-2222", scores)["epss"] == 0.7
    assert epss_service.best_score("CVE-2000-0000", scores) is None
    assert epss_service.best_score(None, scores) is None


@pytest.mark.parametrize("value,band", [(0.9, "high"), (0.5, "high"), (0.49, "medium"), (0.1, "medium"), (0.099, "low"), (0.0, "low")])
def test_epss_bands(value, band):
    assert epss_service.level(value) == band


# ------------------------------------------------------------------ the page
def _findings(owner):
    target = AuthorizedTarget(domain="example.com", owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain="www.example.com")
    db.session.add(asset)
    db.session.commit()
    rows = [
        Vulnerability(asset_id=asset.id, severity="high", title="Log4Shell", cve="CVE-2021-44228", cvss_score=10.0, status="open"),
        Vulnerability(asset_id=asset.id, severity="medium", title="Nginx issue", cve="CVE-2023-2512,CVE-2023-9999", cvss_score=5.3, status="in_progress"),
        Vulnerability(asset_id=asset.id, severity="low", title="Missing security headers", status="open"),
        Vulnerability(asset_id=asset.id, severity="critical", title="Exposed .env", status="in_progress"),
    ]
    db.session.add_all(rows)
    db.session.commit()


@pytest.fixture
def intel_page(client, analyst_user, monkeypatch):
    _findings(analyst_user)
    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({"CVE-2021-44228": (0.9427, 0.9991), "CVE-2023-2512": (0.031, 0.62), "CVE-2023-9999": (0.2, 0.9)}))
    intel = User(username="intel", email="intel@example.com", role=ROLE_THREAT_INTEL)
    intel.set_password("IntelPass#123")
    db.session.add(intel)
    db.session.commit()
    login(client, "intel", "IntelPass#123")
    resp = client.get("/workspace/threat-intel")
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def _rows(html):
    body = re.search(r'<table class="ti-table" data-filterable data-paginate="10">.*?<tbody>(.*?)</tbody>', html, re.S).group(1)
    return re.findall(r"<tr data-severity=.*?</tr>", body, re.S)


def _row(html, title):
    return next(r for r in _rows(html) if title in r)


def test_columns_put_severity_cvss_and_epss_side_by_side(intel_page):
    assert re.search(r"<th>Severity</th><th>CVSS</th><th>EPSS</th>", intel_page)


def test_epss_badge_shows_the_percentage_with_a_colour_band_and_explanation(intel_page):
    high = _row(intel_page, "Log4Shell")
    assert 'class="epss-badge epss-high"' in high and ">94.3%<" in high and "Higher than 100% of all scored CVEs" in high
    assert 'epss-badge epss-low' in _row(intel_page, "Nginx issue") or 'epss-badge epss-medium' in _row(intel_page, "Nginx issue")


def test_a_finding_with_two_cves_shows_the_higher_epss(intel_page):
    row = _row(intel_page, "Nginx issue")
    assert "epss-medium" in row and ">20.0%<" in row


def test_findings_without_a_cve_show_a_dash_not_a_badge(intel_page):
    row = _row(intel_page, "Missing security headers")
    assert "epss-badge" not in row and 'class="epss-none"' in row and "No CVE, so no EPSS score" in row


def test_cvss_is_shown_beside_severity(intel_page):
    assert ">10.0<" in _row(intel_page, "Log4Shell") and ">5.3<" in _row(intel_page, "Nginx issue")


def test_in_progress_and_open_use_clearly_different_badges(intel_page):
    open_row, progress_row = _row(intel_page, "Log4Shell"), _row(intel_page, "Nginx issue")
    assert 'class="status-badge status-open">open<' in open_row
    assert 'class="status-badge status-in_progress">in progress<' in progress_row
    assert "status-in_progress" not in open_row and "status-open" not in progress_row


def test_status_badge_styles_are_amber_for_in_progress_and_red_for_open():
    css = open("static/css/workspace.css", encoding="utf-8").read()
    assert re.search(r"\.status-open\s*\{[^}]*color:\s*#ff6b63", css)
    assert re.search(r"\.status-in_progress\s*\{[^}]*color:\s*#f5b942", css)
    assert re.search(r"\.status-badge\s*\{[^}]*border:\s*1px solid currentColor", css)   # the border takes each badge's own colour


def test_search_and_severity_filter_row_sits_above_the_table(intel_page):
    assert 'placeholder="Filter by keyword, CVE, or domain..."' in intel_page
    select = re.search(r'<select id="severity-filter".*?</select>', intel_page, re.S).group(0)
    assert re.findall(r'<option value="([^"]*)">([^<]+)</option>', select) == [("", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
    assert intel_page.index('id="table-search"') < intel_page.index('<table class="ti-table" data-filterable data-paginate="10">')
    assert intel_page.index("<h2>Prioritized findings</h2>") < intel_page.index('id="table-search"')


def test_every_row_carries_its_severity_and_searchable_text(intel_page):
    rows = _rows(intel_page)
    assert sorted(re.search(r'data-severity="(\w+)"', r).group(1) for r in rows) == ["critical", "high", "low", "medium"]
    search = re.search(r'data-search="([^"]*)"', _row(intel_page, "Nginx issue")).group(1)
    assert "CVE-2023-2512" in search and "CVE-2023-9999" in search and "example.com" in search and "in progress" in search


def test_cves_link_to_the_nvd_and_multiple_ids_get_separate_links(intel_page):
    single = _row(intel_page, "Log4Shell")
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"' in single and 'rel="noopener noreferrer"' in single and 'target="_blank"' in single

    multi = _row(intel_page, "Nginx issue")
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2023-2512"' in multi and 'href="https://nvd.nist.gov/vuln/detail/CVE-2023-9999"' in multi
    assert "CVE-2023-2512,CVE-2023-9999" not in multi     # no more one broken link for the combined string


def test_findings_without_a_cve_are_not_linked(intel_page):
    assert "nvd.nist.gov" not in _row(intel_page, "Missing security headers")


def test_the_page_still_renders_when_the_epss_service_is_down(client, analyst_user, monkeypatch):
    _findings(analyst_user)

    def down(url):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(epss_service, "_fetch_json", down)
    intel = User(username="intel2", email="intel2@example.com", role=ROLE_THREAT_INTEL)
    intel.set_password("IntelPass#123")
    db.session.add(intel)
    db.session.commit()
    login(client, "intel2", "IntelPass#123")

    resp = client.get("/workspace/threat-intel")

    html = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "epss-badge" not in html and "Log4Shell" in html


def test_analysts_still_cannot_open_the_page(client, analyst_user):
    login(client, "analyst", "AnalystPass123!")
    assert client.get("/workspace/threat-intel").status_code == 302


# ------------------------------------------------------------------ ten rows to a page
def _many_findings(owner, count):
    target = AuthorizedTarget(domain="many.example.com", owner_id=owner.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain="www.many.example.com")
    db.session.add(asset)
    db.session.commit()
    db.session.add_all([
        Vulnerability(asset_id=asset.id, severity="high", title=f"Finding number {i}", cve=f"CVE-2024-{1000 + i}", cvss_score=7.5, kev=True, status="open")
        for i in range(count)
    ])
    db.session.commit()


def _page_as_intel(client, monkeypatch, entries=()):
    monkeypatch.setattr(threat_intel, "recent_kev_entries", lambda limit=10: list(entries)[:limit])
    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({}))
    intel = User(username="intel3", email="intel3@example.com", role=ROLE_THREAT_INTEL)
    intel.set_password("IntelPass#123")
    db.session.add(intel)
    db.session.commit()
    login(client, "intel3", "IntelPass#123")
    return client.get("/workspace/threat-intel").get_data(as_text=True)


def test_the_findings_and_both_kev_tables_are_paged_ten_rows_at_a_time(client, analyst_user, monkeypatch):
    _many_findings(analyst_user, 35)
    entries = [{"cveID": f"CVE-2025-{i:04d}", "vendorProject": "Vendor", "product": "Product", "dateAdded": "2025-01-01", "dueDate": "2025-02-01"} for i in range(25)]

    html = _page_as_intel(client, monkeypatch, entries)

    assert html.count('data-paginate="10"') == 3                                                        # KEV matches, prioritized findings, KEV catalog
    for heading in ("Exposure matched against CISA KEV", "Prioritized findings", "CISA KEV catalog: recent additions"):
        section = html.split(f"<h2>{heading}</h2>")[1].split("</section>")[0]
        assert 'data-paginate="10"' in section, heading
    assert len(_rows(html)) == 35                                                                       # every row is sent; the page script shows ten


def test_the_pager_and_filter_scripts_are_both_loaded_in_the_right_order(client, analyst_user, monkeypatch):
    html = _page_as_intel(client, monkeypatch)
    filter_at, pager_at = html.index("js/table-filter.js"), html.index("js/table-pager.js")
    assert filter_at < pager_at


def test_the_kev_catalog_feed_is_long_enough_to_need_a_second_page(client, analyst_user, monkeypatch):
    asked = []
    monkeypatch.setattr(threat_intel, "recent_kev_entries", lambda limit=10: asked.append(limit) or [])
    monkeypatch.setattr(epss_service, "_fetch_json", _epss_api({}))
    intel = User(username="intel4", email="intel4@example.com", role=ROLE_THREAT_INTEL)
    intel.set_password("IntelPass#123")
    db.session.add(intel)
    db.session.commit()
    login(client, "intel4", "IntelPass#123")

    client.get("/workspace/threat-intel")

    assert asked == [30]
