"""CISA Known Exploited Vulnerabilities (KEV) catalog lookup.

The KEV catalog is CISA's authoritative, freely published list of CVEs
confirmed to be actively exploited in the wild ("weaponized") -- the
strongest publicly available signal for real-world risk, stronger than a
CVSS score alone. No API key or auth is needed; it's a static JSON feed
that CISA updates as new exploited CVEs are confirmed.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import json
import threading
import time
import urllib.error
import urllib.request

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_REQUEST_TIMEOUT_SECONDS = 15
_CACHE_TTL_SECONDS = 6 * 60 * 60  # refresh at most every 6 hours

_lock = threading.Lock()
_cache = {}  # cve_id -> KEV entry dict
_cache_loaded_at = 0.0


def _fetch_catalog():
    request = urllib.request.Request(_KEV_URL, headers={"User-Agent": "attack-surface-management-fyp"})
    with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
        payload = json.load(response)
    return {
        vuln["cveID"]: vuln
        for vuln in payload.get("vulnerabilities", [])
        if vuln.get("cveID")
    }


def _ensure_cache():
    global _cache, _cache_loaded_at
    with _lock:
        if _cache and (time.time() - _cache_loaded_at) < _CACHE_TTL_SECONDS:
            return
        try:
            _cache = _fetch_catalog()
            _cache_loaded_at = time.time()
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            # Keep serving whatever was cached before (even if stale) rather
            # than treating a network hiccup as "nothing is exploited."
            pass


def kev_entry(cve_id: str):
    """Return the KEV catalog entry for `cve_id`, or None if it isn't
    listed (or the CVE id is empty). Never raises on network failure.
    """
    if not cve_id:
        return None
    _ensure_cache()
    return _cache.get(cve_id.strip().upper())


def is_kev(cve_id: str) -> bool:
    return kev_entry(cve_id) is not None


def recent_kev_entries(limit: int = 10):
    """Most recently added KEV catalog entries, for general threat-intel
    awareness (independent of the analyst's own discovered assets).
    """
    _ensure_cache()
    entries = sorted(
        _cache.values(),
        key=lambda v: v.get("dateAdded", ""),
        reverse=True,
    )
    return entries[:limit]


def catalog_size() -> int:
    _ensure_cache()
    return len(_cache)
