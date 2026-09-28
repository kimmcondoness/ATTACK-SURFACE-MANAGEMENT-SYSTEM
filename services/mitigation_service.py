"""Mitigation guidance for a finding: the concrete steps that reduce or remove
its risk, and a suggested timeframe.

Rule-based, not AI-generated: a finding gets steps from the first rule its
title matches, else CVE-style steps if it carries a CVE, else whatever
recommendation the scanner stored, else a generic fallback. Nothing here
claims a finding is confirmed; steps that depend on it being real say to
verify first.
"""

_TIMEFRAMES = {
    "critical": "Immediately (within 24 to 72 hours)",
    "high": "Within 7 days",
    "medium": "Within 30 days",
    "low": "Next scheduled maintenance window",
}

# Substrings that mean the scanned banner belongs to a CDN/proxy edge rather
# than the origin server, so a CVE keyword-matched on it is probably about
# somebody else's software.
_EDGE_MARKERS = ("cloudflare", "akamai", "cloudfront", "fastly", "heroku-router")

_CVE_MATCH_NOTE_PREFIX = "Matched via an NVD keyword search"

# Findings from the built-in checks (scanner/exposure_scanner.py, scanner/config_scanner.py) carry
# their own mitigation steps, one per line.
_EXPOSURE_TITLE_PREFIXES = ("[dork] ", "[config] ")
_EXPOSURE_CLOSING_STEP = "Re-run the scan to confirm the exposure is gone."

_TITLE_RULES = [
    (
        ("security header", "x-frame-options", "content-security-policy"),
        [
            "Add a Content-Security-Policy header that lists the sources your pages really load from.",
            "Add X-Frame-Options: DENY (or CSP frame-ancestors) so the site cannot be embedded in another page.",
            "Add X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin and, on HTTPS-only sites, Strict-Transport-Security.",
            "Set them once in the web server or reverse proxy config, then confirm with your browser's developer tools (Network tab, response headers).",
        ],
    ),
    (
        ("version disclosure", "server banner", "x-powered-by"),
        [
            "Stop the server advertising its software and version. nginx: set server_tokens off. Apache: set ServerTokens Prod and ServerSignature Off. IIS: remove the X-Powered-By header.",
            "Remove framework headers such as X-Powered-By and X-AspNet-Version at the application or proxy layer.",
            "This is defence in depth: hiding a version does not fix an old version, so keep the software patched as well.",
        ],
    ),
    (
        ("directory listing", "index of"),
        [
            "Turn off automatic directory indexes. nginx: set autoindex off. Apache: use Options -Indexes.",
            "Review what was exposed and move anything sensitive out of the web root.",
        ],
    ),
    (
        (".env", ".git", "backup file", "exposed file", "sensitive file"),
        [
            "Remove the file from the web root, or block it in the server config (deny access to dotfiles, .git and backup extensions).",
            "Assume anything inside it was read: rotate every password, API key and token it contained.",
            "Check access logs for earlier requests to that path.",
        ],
    ),
    (
        ("ssl", "tls", "certificate"),
        [
            "Disable SSLv3, TLS 1.0 and TLS 1.1; allow TLS 1.2 and 1.3 only.",
            "Remove weak cipher suites and renew any expired or self-signed certificate.",
            "Re-test the endpoint with a TLS scanner after the change.",
        ],
    ),
    (
        ("cookie", "httponly", "samesite"),
        [
            "Set the HttpOnly, Secure and SameSite attributes on session and authentication cookies.",
        ],
    ),
    (
        ("admin panel", "login portal", "phpmyadmin", "exposed panel"),
        [
            "Take the panel off the public internet: restrict it by IP allowlist, VPN or an authenticating reverse proxy.",
            "Enforce strong passwords and multi-factor authentication on it, and remove any default credentials.",
        ],
    ),
]

_GENERIC_STEPS = [
    "Confirm the finding on the affected asset and decide whether it is expected.",
    "Apply the fix from the vendor or framework documentation, or restrict access to the affected service.",
    "Re-run the scan to confirm the finding no longer appears.",
]


def _cve_steps(vuln):
    title = (vuln.title or "").lower()
    steps = []
    if any(marker in title for marker in _EDGE_MARKERS):
        steps.append(
            "The banner behind this match belongs to a CDN or proxy edge, not necessarily your own server, "
            "so this CVE probably describes different software. Identify what your origin actually runs "
            "before acting on it."
        )
    else:
        steps.append(
            "Confirm the exact software and version running on the affected service. A banner match is only a lead."
        )
    steps.extend(
        [
            f"Read the NVD entry for {vuln.cve} and the vendor advisory, and check whether your version is in the affected range.",
            "If it is affected, upgrade to the vendor's fixed release, or apply the documented workaround until you can.",
            "If the service does not need to be public, restrict it with a firewall rule, VPN or IP allowlist, or place it behind a WAF.",
            "Re-run the scan afterwards to confirm the finding is gone.",
        ]
    )
    return steps


def _stored_recommendation(vuln):
    text = (vuln.recommendation or "").strip()
    if not text or text.startswith(_CVE_MATCH_NOTE_PREFIX):
        return None
    return text


def timeframe_for(vuln):
    if getattr(vuln, "kev", False):
        return "Immediately: listed in CISA's Known Exploited Vulnerabilities catalog (attackers are using it now)"
    base = _TIMEFRAMES.get((vuln.severity or "").lower(), _TIMEFRAMES["medium"])
    if getattr(vuln, "exploit_available", False) and vuln.severity in ("medium", "low"):
        return f"{base}; sooner, because a public exploit exists"
    return base


def mitigation_for(vuln):
    """Return {"steps": [str, ...], "timeframe": str} for one Vulnerability."""
    title = (vuln.title or "").lower()

    if title.startswith(_EXPOSURE_TITLE_PREFIXES):
        stored_steps = [line.strip() for line in (vuln.recommendation or "").splitlines() if line.strip()]
        if stored_steps:
            if _EXPOSURE_CLOSING_STEP not in stored_steps and not any("re-run" in s.lower() for s in stored_steps):
                stored_steps.append(_EXPOSURE_CLOSING_STEP)
            return {"steps": stored_steps, "timeframe": timeframe_for(vuln)}

    steps = None
    # NVD keyword matches are titled "Possible CVE-...". Their titles embed the
    # service banner (e.g. "ssl|https"), which would trip the title rules below.
    if vuln.cve and "possible cve-" in title:
        steps = _cve_steps(vuln)

    if steps is None:
        for keywords, rule_steps in _TITLE_RULES:
            if any(k in title for k in keywords):
                steps = list(rule_steps)
                break

    if steps is None and vuln.cve:
        steps = _cve_steps(vuln)
    if steps is None:
        stored = _stored_recommendation(vuln)
        steps = [stored] + _GENERIC_STEPS[1:] if stored else list(_GENERIC_STEPS)

    return {"steps": steps, "timeframe": timeframe_for(vuln)}
