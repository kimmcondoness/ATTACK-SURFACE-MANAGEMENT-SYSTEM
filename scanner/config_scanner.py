"""Built-in checks for common security misconfigurations on a web host.

These run on every vulnerability scan, whether or not Nuclei is installed, so the
"misconfiguration" half of the scan is always real. Everything is a normal request a
browser would make (a few GETs, one TRACE, one TLS handshake) against a host the owner
has authorized; nothing is exploited and nothing is guessed at.

Checks:
  * HTTPS: not offered at all, or HTTP that does not redirect to it
  * TLS certificate: expired, wrong hostname, not trusted, expiring soon; TLS 1.0/1.1 accepted
  * Security headers: HSTS, Content-Security-Policy, clickjacking protection,
    X-Content-Type-Options, Referrer-Policy
  * Information disclosure: version numbers in Server / X-Powered-By / X-AspNet-Version
  * Cookies missing Secure / HttpOnly
  * CORS that lets any website read responses; HTTP TRACE enabled

Only a real page (a 2xx response) is judged: an error or block page (401/403/429/503) or a
redirect to another site says nothing about this host, so a WAF challenge can never be
reported as "missing headers".
"""

import http.client
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from scanner.base import ScanControl, ScannerResult

USER_AGENT = "ASM-ConfigCheck/1.0 (authorized security assessment)"
TIMEOUT_SECONDS = 6
MAX_BODY_BYTES = 16 * 1024
MAX_REDIRECTS = 3
TITLE_PREFIX = "[Config] "
CERT_WARNING_DAYS = 14
_REDIRECTS = (301, 302, 303, 307, 308)
_BLOCKED = (401, 403, 406, 429, 503)
_SESSION_LIKE = re.compile(r"sess|sid|token|auth|jwt|login|csrf|xsrf", re.IGNORECASE)
_HAS_VERSION = re.compile(r"\d+\.\d+")

_INSECURE_TLS = ssl.create_default_context()
_INSECURE_TLS.check_hostname = False
_INSECURE_TLS.verify_mode = ssl.CERT_NONE


@dataclass(frozen=True)
class Page:
    url: str
    status: int
    headers: Dict[str, str]
    cookies: List[str] = field(default_factory=list)
    body: bytes = b""


Fetch = Callable[..., Optional[Page]]
TlsProbe = Callable[[str, int], dict]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_fetch(url: str, method: str = "GET", headers: Optional[dict] = None) -> Optional[Page]:
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_INSECURE_TLS))
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as resp:
            return _page(url, resp.status, resp.headers, resp.read(MAX_BODY_BYTES))
    except urllib.error.HTTPError as err:
        try:
            body = err.read(MAX_BODY_BYTES)
        except (OSError, http.client.HTTPException):
            body = b""
        return _page(url, err.code, err.headers, body)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return None


def _page(url, status, headers, body) -> Page:
    return Page(url, status, {k.lower(): v for k, v in headers.items()}, list(headers.get_all("Set-Cookie") or []), body)


def _classify_certificate_error(error: ssl.SSLCertVerificationError) -> str:
    code = getattr(error, "verify_code", 0)
    if code == 10:
        return "expired"
    if code in (62, 64):
        return "hostname"
    return "untrusted"


def tls_probe(hostname: str, port: int = 443) -> dict:
    """{"error": None | "expired" | "hostname" | "untrusted", "days_left": int | None,
    "legacy": [ "TLS 1.0", ...], "unreachable": bool}"""
    result = {"error": None, "days_left": None, "legacy": [], "unreachable": False}
    try:
        with socket.create_connection((hostname, port), TIMEOUT_SECONDS) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls:
                not_after = tls.getpeercert().get("notAfter")
                if not_after:
                    result["days_left"] = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
    except ssl.SSLCertVerificationError as exc:
        result["error"] = _classify_certificate_error(exc)
    except (ssl.SSLError, OSError):
        result["unreachable"] = True
        return result

    for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = context.maximum_version = version
            context.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((hostname, port), TIMEOUT_SECONDS) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    result["legacy"].append(label)
        except (ssl.SSLError, OSError, ValueError):
            continue   # refused, or this Python/OpenSSL cannot speak that version: nothing to report
    return result


def _finding(severity: str, title: str, description: str, steps) -> dict:
    return {
        "severity": severity,
        "cve": None,
        "title": TITLE_PREFIX + title,
        "description": description,
        "recommendation": "\n".join(steps),
    }


_RERUN = "Re-run the scan to confirm the finding is gone."


class ConfigScanner:
    source = "real"

    def __init__(self, fetch: Fetch = http_fetch, tls: TlsProbe = tls_probe):
        self._fetch = fetch
        self._tls = tls

    # ------------------------------------------------------------------ helpers
    def _follow(self, url: str) -> Optional[Page]:
        """GET a page, following up to three redirects that stay on the same host."""
        page = self._fetch(url)
        host = urlparse(url).hostname
        for _ in range(MAX_REDIRECTS):
            if page is None or page.status not in _REDIRECTS or "location" not in page.headers:
                break
            target = urljoin(page.url, page.headers["location"])
            if urlparse(target).hostname != host:
                break
            following = self._fetch(target)
            if following is None:
                break
            page = following
        return page

    @staticmethod
    def _split(host: str):
        parsed = urlparse(host if "//" in host else f"//{host}")
        return parsed.hostname or host, parsed.port

    # ---------------------------------------------------------------------- run
    def run(self, host: str, control: Optional[ScanControl] = None) -> ScannerResult:
        hostname, port = self._split(host)
        netloc = f"{hostname}:{port}" if port else hostname
        stopped = lambda: bool(control and control.stop_requested())   # noqa: E731

        https_page = self._follow(f"https://{netloc}/")
        http_first = self._fetch(f"http://{netloc}/")
        if https_page is None and http_first is None:
            return ScannerResult(success=True, source=self.source, raw_output="unreachable")
        if stopped():
            return ScannerResult(success=True, source=self.source, stopped=True)

        page = https_page or self._follow(f"http://{netloc}/")
        findings: List[dict] = []

        if not port:
            findings += self._https_findings(hostname, https_page, http_first)
        if page is not None and 200 <= page.status < 300:   # a redirect off this host, or an error, is not this host's page
            findings += self._header_findings(page, secure=page.url.startswith("https://"))
            findings += self._cookie_findings(page, secure=page.url.startswith("https://"))
            findings += self._cors_and_trace(page.url)
        if https_page is not None and not port and not stopped():
            findings += self._tls_findings(hostname)

        seen, unique = set(), []
        for item in findings:
            if item["title"] not in seen:
                seen.add(item["title"])
                unique.append(item)
        return ScannerResult(success=True, source=self.source, data=unique, raw_output="checked")

    # ------------------------------------------------------------------- checks
    def _https_findings(self, hostname, https_page, http_first) -> List[dict]:
        if https_page is None:
            return [_finding(
                "high", "HTTPS is not available",
                f"{hostname} answers on http:// but not on https://, so logins, cookies and page content travel unencrypted.",
                ("Install a TLS certificate (Let's Encrypt issues them free) and serve the site on port 443.",
                 "Redirect all HTTP traffic to HTTPS and add a Strict-Transport-Security header.", _RERUN))]
        if http_first is None or http_first.status >= 400:
            return []
        location = http_first.headers.get("location", "")
        if http_first.status in _REDIRECTS and location.startswith("https://"):
            return []
        return [_finding(
            "medium", "HTTP does not redirect to HTTPS",
            f"http://{hostname}/ answered with status {http_first.status} instead of redirecting to https://, so visitors who "
            "type the plain address stay on an unencrypted connection.",
            ("Redirect every http:// request to the same address on https:// (a 301 redirect in the web server or CDN).",
             "Add a Strict-Transport-Security header so browsers stop using HTTP at all.", _RERUN))]

    def _header_findings(self, page: Page, secure: bool) -> List[dict]:
        headers, found = page.headers, []
        csp = headers.get("content-security-policy", "")

        def missing(name, severity, why, steps):
            found.append(_finding(severity, f"Missing security header: {name}",
                                  f"The response from {page.url} has no {name} header. {why}", steps + (_RERUN,)))

        if secure and "strict-transport-security" not in headers:
            missing("Strict-Transport-Security", "medium",
                    "Without HSTS a browser can be tricked into using plain HTTP.",
                    ("Send Strict-Transport-Security: max-age=31536000; includeSubDomains from the web server or CDN.",))
        if not csp:
            missing("Content-Security-Policy", "medium",
                    "A CSP limits which scripts and resources a page may load, which blunts cross-site scripting.",
                    ("Add a Content-Security-Policy that lists only the sources your pages really load from.",
                     "Start in report-only mode (Content-Security-Policy-Report-Only), then enforce it."))
        if "x-frame-options" not in headers and "frame-ancestors" not in csp:
            found.append(_finding(
                "medium", "Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                f"{page.url} can be embedded in another site's frame, which enables clickjacking.",
                ("Send X-Frame-Options: DENY (or SAMEORIGIN), or a CSP with frame-ancestors 'none' / 'self'.", _RERUN)))
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            missing("X-Content-Type-Options", "low", "Browsers may guess a file's type and run it as script.",
                    ("Send X-Content-Type-Options: nosniff.",))
        if "referrer-policy" not in headers:
            missing("Referrer-Policy", "low", "Full page addresses, which can hold tokens, may leak to other sites.",
                    ("Send Referrer-Policy: strict-origin-when-cross-origin.",))

        for name, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"), ("x-aspnet-version", "X-AspNet-Version")):
            value = headers.get(name)
            if not value or (name == "server" and not _HAS_VERSION.search(value)):
                continue
            kind = "Server version disclosed" if name == "server" else "Technology disclosed"
            found.append(_finding(
                "low", f"{kind}: {label}: {value}",
                f"{page.url} tells every visitor it runs '{value}' in the {label} header, which makes it easy to look up "
                "known vulnerabilities for that exact version.",
                ("Stop the server advertising it (nginx: server_tokens off; Apache: ServerTokens Prod; "
                 "remove X-Powered-By at the application or proxy).",
                 "Hiding a version does not fix an old one: keep the software patched too.", _RERUN)))
        return found

    def _cookie_findings(self, page: Page, secure: bool) -> List[dict]:
        weak, session_like = [], False
        for raw in page.cookies:
            name = raw.split("=", 1)[0].strip()
            flags = raw.lower()
            lacking = []
            if secure and "secure" not in flags:
                lacking.append("Secure")
            if "httponly" not in flags:
                lacking.append("HttpOnly")
            if lacking:
                weak.append(name)
                session_like = session_like or bool(_SESSION_LIKE.search(name))
        if not weak:
            return []
        names = sorted(set(weak))
        shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        return [_finding(
            "medium" if session_like else "low", f"Cookie missing security flags: {shown}",
            f"{page.url} sets cookies without the Secure and/or HttpOnly flag ({', '.join(names)}). Without HttpOnly a script "
            "can read the cookie; without Secure it can be sent over plain HTTP.",
            ("Set HttpOnly and Secure (and SameSite=Lax or Strict) on every session and authentication cookie.", _RERUN))]

    def _cors_and_trace(self, url: str) -> List[dict]:
        found = []
        probe = self._fetch(url, headers={"Origin": "https://asm-cors-check.invalid"})
        if probe is not None:
            allow = probe.headers.get("access-control-allow-origin", "")
            credentials = probe.headers.get("access-control-allow-credentials", "").lower() == "true"
            if allow == "https://asm-cors-check.invalid":
                found.append(_finding(
                    "high" if credentials else "medium", "CORS allows any website to read responses",
                    f"{url} echoed back an arbitrary Origin in Access-Control-Allow-Origin"
                    + (" and allows credentials, so any website a logged-in user visits can read their data." if credentials
                       else ", so any website can read its responses."),
                    ("Allow only an explicit list of trusted origins instead of reflecting the request's Origin.",
                     "Never combine a reflected or wildcard origin with Access-Control-Allow-Credentials: true.", _RERUN)))
        trace = self._fetch(url, method="TRACE")
        if trace is not None and trace.status == 200 and (
            "message/http" in trace.headers.get("content-type", "") or b"TRACE" in trace.body[:200]
        ):
            found.append(_finding(
                "medium", "HTTP TRACE method is enabled",
                f"{url} answers TRACE requests by echoing them back, which can expose headers such as cookies to scripts (cross-site tracing).",
                ("Disable TRACE (Apache: TraceEnable off; nginx: it is off unless a proxy re-enables it).", _RERUN)))
        return found

    def _tls_findings(self, hostname: str) -> List[dict]:
        probe = self._tls(hostname, 443)
        if probe.get("unreachable"):
            return []
        found = []
        error, days_left = probe.get("error"), probe.get("days_left")
        if error == "expired":
            found.append(_finding("high", "TLS certificate has expired",
                                  f"The certificate {hostname} presents on port 443 has expired, so browsers show a security warning and connections cannot be trusted.",
                                  ("Renew the certificate now and install the new one.", "Automate renewal (for example certbot) so it cannot lapse again.", _RERUN)))
        elif error == "hostname":
            found.append(_finding("high", "TLS certificate does not match the hostname",
                                  f"The certificate presented for {hostname} was issued for a different name, so browsers reject the connection.",
                                  ("Issue a certificate that covers this exact hostname (or a matching wildcard) and install it.", _RERUN)))
        elif error:
            found.append(_finding("medium", "TLS certificate is not trusted",
                                  f"The certificate presented for {hostname} is self-signed or issued by an authority browsers do not trust.",
                                  ("Replace it with a certificate from a public CA (Let's Encrypt is free).",
                                   "If the chain is incomplete, install the intermediate certificate as well.", _RERUN)))
        elif days_left is not None and days_left <= CERT_WARNING_DAYS:
            found.append(_finding("high" if days_left <= 3 else "medium", f"TLS certificate expires in {max(days_left, 0)} days",
                                  f"The certificate for {hostname} expires soon. When it lapses, browsers will block the site.",
                                  ("Renew and deploy the certificate before it expires.", "Automate renewal so this cannot recur.", _RERUN)))
        if probe.get("legacy"):
            versions = " and ".join(probe["legacy"])
            found.append(_finding("medium", f"Deprecated TLS versions accepted: {versions}",
                                  f"{hostname} still negotiates {versions}, which have known weaknesses and were retired by the IETF.",
                                  ("Allow only TLS 1.2 and TLS 1.3 in the web server or load balancer.", _RERUN)))
        return found
