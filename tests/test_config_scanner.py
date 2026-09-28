import ssl

import pytest

from scanner.base import ScanControl
from scanner.config_scanner import ConfigScanner, Page, _classify_certificate_error

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}
HTTPS_REDIRECT = Page("http://example.com/", 301, {"location": "https://example.com/"})
CLEAN_TLS = {"error": None, "days_left": 200, "legacy": [], "unreachable": False}


def site(https=None, http=HTTPS_REDIRECT, extra=None):
    """A fake network. `https` / `http` are the responses for "/" on each scheme;
    `extra` maps (method, header-marker) -> response for the CORS / TRACE probes."""
    extra = extra or {}

    def fetch(url, method="GET", headers=None):
        if method == "TRACE":
            return extra.get("trace")
        if headers and "Origin" in headers:
            return extra.get("cors", https)
        return https if url.startswith("https://") else http

    return fetch


def page(headers=None, cookies=(), status=200, url="https://example.com/", body=b""):
    return Page(url, status, {k.lower(): v for k, v in (headers or {}).items()}, list(cookies), body)


def run(fetch, tls=CLEAN_TLS, host="example.com"):
    return ConfigScanner(fetch=fetch, tls=lambda hostname, port: tls).run(host)


def titles(result):
    return [f["title"] for f in result.data]


def test_a_well_configured_site_has_no_findings():
    assert run(site(https=page(GOOD_HEADERS))).data == []


def test_every_finding_is_a_real_finding_shape():
    result = run(site(https=page({}, cookies=["sessionid=abc; Path=/"])))
    assert result.success and result.source == "real" and result.data
    for f in result.data:
        assert f["title"].startswith("[Config] ") and f["cve"] is None
        assert f["severity"] in ("critical", "high", "medium", "low") and f["description"] and f["recommendation"].count("\n") >= 1


def test_missing_security_headers_are_reported_individually():
    result = run(site(https=page({})))
    assert set(titles(result)) == {
        "[Config] Missing security header: Strict-Transport-Security",
        "[Config] Missing security header: Content-Security-Policy",
        "[Config] Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
        "[Config] Missing security header: X-Content-Type-Options",
        "[Config] Missing security header: Referrer-Policy",
    }


def test_csp_frame_ancestors_counts_as_clickjacking_protection():
    headers = {**GOOD_HEADERS, "content-security-policy": "frame-ancestors 'none'"}
    headers.pop("x-frame-options")
    assert run(site(https=page(headers))).data == []


def test_hsts_is_not_demanded_of_a_plain_http_site():
    plain = page({k: v for k, v in GOOD_HEADERS.items() if k != "strict-transport-security"}, url="http://example.com/")
    result = run(site(https=None, http=plain))
    assert titles(result) == ["[Config] HTTPS is not available"]
    assert result.data[0]["severity"] == "high"


def test_http_that_does_not_redirect_is_reported():
    result = run(site(https=page(GOOD_HEADERS), http=page(status=200, url="http://example.com/")))
    assert titles(result) == ["[Config] HTTP does not redirect to HTTPS"]


def test_a_blocked_or_error_response_is_never_judged():
    for status in (401, 403, 429, 503, 500):
        assert run(site(https=page({}, status=status))).data == [], status


def test_same_host_redirects_are_followed_before_headers_are_judged():
    landing = page(GOOD_HEADERS, url="https://example.com/en/")

    def fetch(url, method="GET", headers=None):
        if method != "GET" or headers:
            return None
        if url == "https://example.com/":
            return Page(url, 302, {"location": "/en/"})
        if url == "https://example.com/en/":
            return landing
        return HTTPS_REDIRECT

    assert run(fetch).data == []


def test_a_redirect_to_another_host_is_not_followed():
    def fetch(url, method="GET", headers=None):
        if method != "GET" or headers:
            return None
        return Page(url, 302, {"location": "https://elsewhere.example/"}) if url.startswith("https://") else HTTPS_REDIRECT

    assert run(fetch).data == []   # the page lives on another host, so this one is not judged for it


@pytest.mark.parametrize("value,expected", [
    ("nginx/1.18.0 (Ubuntu)", True), ("Apache/2.4.41", True), ("cloudflare", False), ("nginx", False), ("Microsoft-IIS/10.0", True)])
def test_server_header_is_only_flagged_when_it_reveals_a_version(value, expected):
    result = run(site(https=page({**GOOD_HEADERS, "Server": value})))
    assert any(t.startswith("[Config] Server version disclosed") for t in titles(result)) is expected


def test_powered_by_headers_are_flagged():
    result = run(site(https=page({**GOOD_HEADERS, "X-Powered-By": "PHP/7.4.3", "X-AspNet-Version": "4.0.30319"})))
    assert "[Config] Technology disclosed: X-Powered-By: PHP/7.4.3" in titles(result)
    assert "[Config] Technology disclosed: X-AspNet-Version: 4.0.30319" in titles(result)


def test_cookies_without_flags_are_grouped_and_session_cookies_rank_higher():
    result = run(site(https=page(GOOD_HEADERS, cookies=["sessionid=1; Path=/", "theme=dark; Path=/; Secure; HttpOnly"])))
    [finding] = result.data
    assert finding["title"] == "[Config] Cookie missing security flags: sessionid" and finding["severity"] == "medium"

    plain = run(site(https=page(GOOD_HEADERS, cookies=["theme=dark; Path=/"])))
    assert plain.data[0]["severity"] == "low"


def test_secure_flag_is_not_required_on_plain_http():
    only_http = page(GOOD_HEADERS, cookies=["prefs=1; HttpOnly"], url="http://example.com/")
    result = run(site(https=None, http=only_http))
    assert not any("Cookie" in t for t in titles(result))


def test_a_cookie_with_all_flags_is_fine():
    assert run(site(https=page(GOOD_HEADERS, cookies=["sessionid=1; Secure; HttpOnly; SameSite=Lax"]))).data == []


def test_cors_reflecting_any_origin_is_medium_or_high_with_credentials():
    reflect = page({**GOOD_HEADERS, "Access-Control-Allow-Origin": "https://asm-cors-check.invalid"})
    assert [f["severity"] for f in run(site(https=page(GOOD_HEADERS), extra={"cors": reflect})).data] == ["medium"]

    with_credentials = page({**GOOD_HEADERS, "Access-Control-Allow-Origin": "https://asm-cors-check.invalid", "Access-Control-Allow-Credentials": "true"})
    assert [f["severity"] for f in run(site(https=page(GOOD_HEADERS), extra={"cors": with_credentials})).data] == ["high"]

    wildcard = page({**GOOD_HEADERS, "Access-Control-Allow-Origin": "*"})
    assert run(site(https=page(GOOD_HEADERS), extra={"cors": wildcard})).data == []


def test_trace_is_only_flagged_when_the_server_really_echoes_it():
    echo = page(status=200, headers={"content-type": "message/http"})
    assert titles(run(site(https=page(GOOD_HEADERS), extra={"trace": echo}))) == ["[Config] HTTP TRACE method is enabled"]
    for refused in (page(status=405), page(status=501), page(status=200, body=b"<html>hello</html>"), None):
        assert run(site(https=page(GOOD_HEADERS), extra={"trace": refused})).data == []


@pytest.mark.parametrize("error,title,severity", [
    ("expired", "[Config] TLS certificate has expired", "high"),
    ("hostname", "[Config] TLS certificate does not match the hostname", "high"),
    ("untrusted", "[Config] TLS certificate is not trusted", "medium")])
def test_certificate_problems(error, title, severity):
    result = run(site(https=page(GOOD_HEADERS)), tls={**CLEAN_TLS, "error": error, "days_left": None})
    assert [(f["title"], f["severity"]) for f in result.data] == [(title, severity)]


@pytest.mark.parametrize("days,severity", [(14, "medium"), (5, "medium"), (3, "high"), (0, "high")])
def test_a_certificate_about_to_expire(days, severity):
    result = run(site(https=page(GOOD_HEADERS)), tls={**CLEAN_TLS, "days_left": days})
    assert [(f["title"], f["severity"]) for f in result.data] == [(f"[Config] TLS certificate expires in {days} days", severity)]


def test_a_certificate_with_plenty_of_time_left_is_fine():
    assert run(site(https=page(GOOD_HEADERS)), tls={**CLEAN_TLS, "days_left": 15}).data == []


def test_legacy_tls_versions():
    result = run(site(https=page(GOOD_HEADERS)), tls={**CLEAN_TLS, "legacy": ["TLS 1.0", "TLS 1.1"]})
    assert titles(result) == ["[Config] Deprecated TLS versions accepted: TLS 1.0 and TLS 1.1"]


def test_tls_is_skipped_when_the_probe_cannot_connect():
    assert run(site(https=page(GOOD_HEADERS)), tls={**CLEAN_TLS, "unreachable": True, "error": "expired"}).data == []


def test_unreachable_host_is_a_clean_skip():
    result = run(lambda *a, **k: None)
    assert result.success and result.data == [] and result.raw_output == "unreachable"


def test_stop_request_ends_the_scan_early():
    control = ScanControl()
    control.request_stop()
    result = ConfigScanner(fetch=site(https=page({})), tls=lambda h, p: CLEAN_TLS).run("example.com", control=control)
    assert result.stopped and result.data == []


def test_a_custom_port_is_judged_only_on_what_it_serves():
    seen = []

    def fetch(url, method="GET", headers=None):
        seen.append(url)
        return page(GOOD_HEADERS, url=url) if url.startswith("https://") else None

    result = run(fetch, host="https://example.com:8443")
    assert result.data == [] and all(":8443" in u for u in seen)


def test_findings_are_not_repeated():
    result = run(site(https=page({"Server": "nginx/1.1", "X-Powered-By": "PHP/7"})))
    assert len(titles(result)) == len(set(titles(result)))


def test_certificate_error_codes_are_classified():
    def error(code):
        exc = ssl.SSLCertVerificationError()
        exc.verify_code = code
        return exc

    assert _classify_certificate_error(error(10)) == "expired"
    assert _classify_certificate_error(error(62)) == "hostname"
    assert _classify_certificate_error(error(64)) == "hostname"
    assert _classify_certificate_error(error(18)) == "untrusted"
    assert _classify_certificate_error(error(20)) == "untrusted"


def test_config_findings_carry_their_own_mitigation_steps_and_report_marker(app):
    from extensions import db
    from models import Asset, AuthorizedTarget, User, Vulnerability
    from services import report_service
    from services.mitigation_service import mitigation_for

    user = User(username="cfg", email="cfg@example.com", role="cybersecurity_analyst")
    user.set_password("CfgPass#12345")
    db.session.add(user)
    db.session.commit()
    target = AuthorizedTarget(domain="example.com", owner_id=user.id, authorized=True)
    db.session.add(target)
    db.session.commit()
    asset = Asset(target_id=target.id, subdomain="www.example.com")
    db.session.add(asset)
    db.session.commit()
    result = run(site(https=page({})))
    for item in result.data:
        db.session.add(Vulnerability(asset_id=asset.id, severity=item["severity"], title=item["title"], description=item["description"], recommendation=item["recommendation"]))
    db.session.commit()

    vuln = Vulnerability.query.filter(Vulnerability.title.like("%Content-Security-Policy")).one()
    steps = mitigation_for(vuln)["steps"]
    assert steps[0].startswith("Add a Content-Security-Policy") and steps[-1].startswith("Re-run the scan")   # its own steps, not a generic rule

    data = report_service._build_report_data(target, user.id)
    assert data["findings"] and all(f["config"] and not f["dork"] for f in data["findings"])
