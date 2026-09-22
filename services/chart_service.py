from calendar import month_abbr
from datetime import datetime, timedelta

from models import Asset, Scan, Vulnerability

CHART_HEIGHT_PX = 130
_MIN_VISIBLE_PX = 2

RANGES = ("1m", "3m", "6m", "12m")
_DEFAULT_RANGE = "12m"
_RANGE_MONTHS = {"3m": 3, "6m": 6, "12m": 12}


def normalize_range(value) -> str:
    return value if value in RANGES else _DEFAULT_RANGE


def _last_n_months(n, reference=None):
    reference = reference or datetime.utcnow()
    months = []
    y, m = reference.year, reference.month
    for i in range(n - 1, -1, -1):
        mm = m - i
        yy = y
        while mm <= 0:
            mm += 12
            yy -= 1
        months.append((yy, mm))
    return months


def _last_n_days(n, reference=None):
    reference = (reference or datetime.utcnow()).date()
    return [reference - timedelta(days=i) for i in range(n - 1, -1, -1)]


def _scale(rows, keys):
    max_total = max((sum(row[k] for k in keys) for row in rows), default=0)
    if max_total == 0:
        return rows, 0
    for row in rows:
        total = sum(row[k] for k in keys)
        scaled = 0
        for k in keys:
            px = round(row[k] * CHART_HEIGHT_PX / max_total) if row[k] else 0
            if row[k] and px < _MIN_VISIBLE_PX:
                px = _MIN_VISIBLE_PX
            row[f"{k}_px"] = px
            scaled += px
        row["total"] = total
    return rows, max_total


def _bucket_keys(range_key):
    """Return (bucket_keys, label_for, key_for_datetime) for a range.

    "1m" buckets by day over the last 30 days (a single monthly bucket
    would be one bar, which isn't a useful chart); "3m"/"6m"/"12m" bucket
    by calendar month as before.
    """
    if range_key == "1m":
        days = _last_n_days(30)
        return days, (lambda d: f"{month_abbr[d.month]} {d.day}"), (lambda dt: dt.date())

    months = _last_n_months(_RANGE_MONTHS[range_key])
    return months, (lambda ym: month_abbr[ym[1]]), (lambda dt: (dt.year, dt.month))


def scan_activity_series(target_ids, range_key=_DEFAULT_RANGE):
    range_key = normalize_range(range_key)
    keys, label_for, key_for = _bucket_keys(range_key)
    buckets = {key: {"completed": 0, "failed": 0, "other": 0} for key in keys}

    if target_ids:
        scans = Scan.query.filter(Scan.target_id.in_(target_ids)).all()
        for scan in scans:
            if not scan.started_at:
                continue
            key = key_for(scan.started_at)
            if key not in buckets:
                continue
            if scan.status == "completed":
                buckets[key]["completed"] += 1
            elif scan.status == "failed":
                buckets[key]["failed"] += 1
            else:
                buckets[key]["other"] += 1

    rows = [{"label": label_for(key), **buckets[key]} for key in keys]
    return _scale(rows, ("completed", "failed", "other"))


def scan_status_totals(target_ids, range_key=_DEFAULT_RANGE):
    rows, _ = scan_activity_series(target_ids, range_key)
    return {
        "completed": sum(r["completed"] for r in rows),
        "failed": sum(r["failed"] for r in rows),
        "other": sum(r["other"] for r in rows),
    }


def severity_totals(target_ids, range_key=_DEFAULT_RANGE):
    rows, _ = finding_trend_series(target_ids, range_key)
    return {
        "critical": sum(r["critical"] for r in rows),
        "high": sum(r["high"] for r in rows),
        "medium": sum(r["medium"] for r in rows),
        "low": sum(r["low"] for r in rows),
    }


def finding_trend_series(target_ids, range_key=_DEFAULT_RANGE):
    range_key = normalize_range(range_key)
    keys, label_for, key_for = _bucket_keys(range_key)
    buckets = {key: {"critical": 0, "high": 0, "medium": 0, "low": 0} for key in keys}

    if target_ids:
        vulns = (
            Vulnerability.query.join(Asset)
            .filter(Asset.target_id.in_(target_ids))
            .all()
        )
        for vuln in vulns:
            if not vuln.discovered_at:
                continue
            key = key_for(vuln.discovered_at)
            if key not in buckets:
                continue
            if vuln.severity in buckets[key]:
                buckets[key][vuln.severity] += 1

    rows = [{"label": label_for(key), **buckets[key]} for key in keys]
    return _scale(rows, ("critical", "high", "medium", "low"))
