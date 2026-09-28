"""EPSS (Exploit Prediction Scoring System) lookups.

EPSS is FIRST.org's daily-updated estimate of the probability that a CVE will be
exploited in the wild in the next 30 days. It complements CVSS (how bad a bug is)
and CISA KEV (already exploited): a medium-CVSS bug with a 90% EPSS deserves attention
before a critical one nobody is attacking. No API key is needed.

https://www.first.org/epss/api

Lookups are batched, cached in memory for a day (including "no score published"), and
never raise: if FIRST.org is unreachable the page simply shows no EPSS for uncached CVEs.
"""

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_API_URL = "https://api.first.org/data/v1/epss"
_REQUEST_TIMEOUT_SECONDS = 4
_CACHE_TTL_SECONDS = 24 * 60 * 60
_BATCH_SIZE = 80          # keeps the query string well under URL length limits

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_lock = threading.Lock()
_cache = {}               # cve id -> (score dict or None, fetched_at)


def cve_ids(value) -> list:
    """The valid CVE ids inside a stored finding's `cve` field, in order.

    Nuclei can store several ids in one field ("CVE-2021-1,CVE-2021-2"), so this
    splits them, drops anything that is not a CVE id, and removes duplicates."""
    seen = []
    for match in _CVE_RE.findall(value or ""):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def _fetch_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "attack-surface-management-fyp"})
    with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
        return json.load(response)


def _fetch_batch(batch: list) -> dict:
    payload = _fetch_json(f"{_API_URL}?cve={urllib.parse.quote(','.join(batch), safe=',')}")
    found = {}
    for row in payload.get("data", []):
        try:
            found[row["cve"].upper()] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
        except (KeyError, TypeError, ValueError):
            continue
    return found


def lookup(cves) -> dict:
    """{cve id: {"epss": 0..1, "percentile": 0..1}} for every CVE that has a score."""
    wanted = list(dict.fromkeys(c.upper() for c in cves if _CVE_RE.fullmatch(c or "")))
    now = time.time()
    result, missing = {}, []

    with _lock:
        for cve in wanted:
            cached = _cache.get(cve)
            if cached and now - cached[1] < _CACHE_TTL_SECONDS:
                if cached[0] is not None:
                    result[cve] = cached[0]
            else:
                missing.append(cve)

    for start in range(0, len(missing), _BATCH_SIZE):
        batch = missing[start:start + _BATCH_SIZE]
        try:
            found = _fetch_batch(batch)
        except (urllib.error.URLError, OSError, ValueError):
            continue   # unreachable right now: show nothing for these, and try again next time
        with _lock:
            for cve in batch:
                _cache[cve] = (found.get(cve), time.time())
        result.update(found)
    return result


def best_score(cve_field, scores: dict):
    """The highest-EPSS score among the CVEs of one finding, or None."""
    candidates = [scores[c] for c in cve_ids(cve_field) if c in scores]
    return max(candidates, key=lambda s: s["epss"]) if candidates else None


def level(epss: float) -> str:
    """Badge colour band: high (>= 50%), medium (>= 10%), low."""
    return "high" if epss >= 0.5 else "medium" if epss >= 0.1 else "low"


def clear_cache():
    with _lock:
        _cache.clear()
