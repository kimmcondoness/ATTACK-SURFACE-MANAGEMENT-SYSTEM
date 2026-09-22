"""Best-effort CVE enrichment against the public NVD API.

This is a keyword search over CVE descriptions, not a verified CPE
(product+version) match -- NVD's public API only offers accurate CPE
matching if you already know the exact CPE string for the software,
which this project's scanners don't produce. Every match is stored with
a note saying so, so an analyst always sees it as "worth checking" and
never mistakes it for a confirmed vulnerability.
"""

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD's public (unauthenticated) rate limit is 5 requests per rolling 30s
# window. Stay comfortably under that with a fixed minimum gap between
# calls instead of a request counter.
_MIN_INTERVAL_SECONDS = 6.5
_REQUEST_TIMEOUT_SECONDS = 10

_CIRCL_CVE_URL = "https://cve.circl.lu/api/cve/{cve_id}"
_CIRCL_MIN_INTERVAL_SECONDS = 2.0
# Domains that host public proof-of-concept / exploit code. If a CVE
# record's own references point at one of these, that's real evidence a
# public exploit exists -- not a guess. github.com is checked separately
# (see _looks_like_exploit_repo) since most github.com references are
# patches/advisories, not PoC code.
_EXPLOIT_HOST_MARKERS = (
    "exploit-db.com",
    "packetstormsecurity.com",
    "seclists.org/fulldisclosure",
)

_lock = threading.Lock()
_last_call_at = 0.0
_circl_lock = threading.Lock()
_circl_last_call_at = 0.0


def _throttle():
    global _last_call_at
    with _lock:
        wait = _MIN_INTERVAL_SECONDS - (time.time() - _last_call_at)
        if wait > 0:
            time.sleep(wait)
        _last_call_at = time.time()


def _throttle_circl():
    global _circl_last_call_at
    with _circl_lock:
        wait = _CIRCL_MIN_INTERVAL_SECONDS - (time.time() - _circl_last_call_at)
        if wait > 0:
            time.sleep(wait)
        _circl_last_call_at = time.time()


def _score_to_severity(score):
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_severity(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = cvss.get("baseScore")
            severity = entries[0].get("baseSeverity") or cvss.get("baseSeverity")
            return (severity or _score_to_severity(score)).lower(), score
    return "medium", None


def lookup_cves_for_query(query: str, max_results: int = 3):
    """Return up to `max_results` {cve_id, severity, score, description}
    dicts for CVEs whose description matches `query`, or [] on any
    failure (no network, bad/empty query, NVD error, rate limited, etc.)
    -- a lookup failure should never take down a scan.
    """
    query = (query or "").strip()
    if len(query) < 4:
        return []

    _throttle()
    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": max_results})
    url = f"{_NVD_BASE}?{params}"

    try:
        request = urllib.request.Request(url, headers={"User-Agent": "attack-surface-management-fyp"})
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return []

    matches = []
    for item in payload.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        severity, score = _extract_severity(cve.get("metrics", {}))
        matches.append({"cve_id": cve_id, "severity": severity, "score": score, "description": description})
    return matches


def _looks_like_exploit_repo(url: str) -> bool:
    url_lower = url.lower()
    if "github.com" not in url_lower and "gitlab.com" not in url_lower:
        return False
    return any(marker in url_lower for marker in ("/poc", "poc-", "exploit", "-poc"))


def exploit_available(cve_id: str) -> bool:
    """Best-effort check for a publicly known exploit/PoC, via CIRCL's CVE
    API (containers.cna.references on the raw CVE record). Looks for
    reference URLs that point at known exploit/PoC hosts rather than
    guessing -- returns False (not "unknown") on any lookup failure, so a
    network hiccup never fabricates a false "exploit available" claim.
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return False

    _throttle_circl()
    url = _CIRCL_CVE_URL.format(cve_id=cve_id)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "attack-surface-management-fyp"})
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return False

    references = payload.get("containers", {}).get("cna", {}).get("references", [])
    for ref in references:
        tags = [t.lower() for t in ref.get("tags", [])]
        if "exploit" in tags:
            return True
        ref_url = ref.get("url", "")
        if any(marker in ref_url.lower() for marker in _EXPLOIT_HOST_MARKERS):
            return True
        if _looks_like_exploit_repo(ref_url):
            return True
    return False
