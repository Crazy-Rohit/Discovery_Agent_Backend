from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, request, g

from db import ensure_indexes, users, logs, screenshots
from rbac import require_dashboard_access, ROLE_C_SUITE, ROLE_DEPT_HEAD

insights_api = Blueprint("insights_api", __name__)


def ok(data=None, status=200):
    return jsonify({"ok": True, "data": data}), status


def parse_ymd(s: str):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


def daterange(start: datetime, end: datetime):
    d = start
    while d <= end:
        yield d.strftime("%Y-%m-%d")
        d += timedelta(days=1)


def get_range_from_request() -> Tuple[datetime, datetime, str, str]:
    from_s = request.args.get("from") or request.args.get("start")
    to_s = request.args.get("to") or request.args.get("end")

    start = parse_ymd(from_s)
    end = parse_ymd(to_s)

    if not start and not end:
        now = datetime.utcnow()
        start = end = datetime(now.year, now.month, now.day)
    elif start and not end:
        end = start
    elif end and not start:
        start = end

    return start, end, (from_s or start.strftime("%Y-%m-%d")), (to_s or end.strftime("%Y-%m-%d"))


def get_allowed_mac_ids(identity: Dict[str, Any]) -> List[str]:
    role = (identity or {}).get("role_key")
    department = (identity or {}).get("department")

    if role == ROLE_C_SUITE:
        q: Dict[str, Any] = {}
        dep = request.args.get("department")
        if dep:
            q["department"] = dep
        return [u.get("_id") for u in users.find(q, {"_id": 1})]

    if role == ROLE_DEPT_HEAD:
        if not department:
            return []
        return [u.get("_id") for u in users.find({"department": department}, {"_id": 1})]

    return []


def read_bucket(doc: Dict[str, Any], key: str, day: str):
    return (doc.get(key) or {}).get(day, []) or []


def read_archives(col, mac_id: str, key: str, day: str):
    prefix = f"{mac_id}|archive|{key}|{day}|"
    return col.find({"_id": {"$regex": f"^{prefix}"}})


@insights_api.before_app_request
def _init_indexes():
    try:
        ensure_indexes()
    except Exception:
        pass


@insights_api.get("/api/insights/summary")
@require_dashboard_access()
def summary():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)

    start, end, from_s, to_s = get_range_from_request()

    if not mac_ids:
        return ok({"totals": {"unique_users": 0, "logs": 0, "screenshots": 0}, "range": {"from": from_s, "to": to_s}})

    total_logs = 0
    total_shots = 0

    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        for day in daterange(start, end):
            events = list(read_bucket(doc, "logs", day))
            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))
            total_logs += len(events)

    for doc in screenshots.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        for day in daterange(start, end):
            items = list(read_bucket(doc, "screenshots", day))
            for a in read_archives(screenshots, mac, "screenshots", day):
                items.extend(read_bucket(a, "screenshots", day))
            total_shots += len(items)

    return ok({
        "totals": {"unique_users": len(set(mac_ids)), "logs": total_logs, "screenshots": total_shots},
        "range": {"from": from_s, "to": to_s},
    })


@insights_api.get("/api/insights/timeseries")
@require_dashboard_access()
def timeseries():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)

    start, end, from_s, to_s = get_range_from_request()

    labels = list(daterange(start, end))
    if not mac_ids:
        return ok({"labels": labels, "series": [{"name": "Logs", "data": [0 for _ in labels]}]})

    # Count logs per day
    counts = {day: 0 for day in labels}

    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        for day in labels:
            events = list(read_bucket(doc, "logs", day))
            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))
            counts[day] += len(events)

    data = [counts[d] for d in labels]
    return ok({"labels": labels, "series": [{"name": "Logs", "data": data}]})


@insights_api.get("/api/insights/top")
@require_dashboard_access()
def top():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)

    start, end, from_s, to_s = get_range_from_request()

    by = (request.args.get("by") or "category").strip().lower()
    limit = max(min(int(request.args.get("limit") or 10), 50), 1)

    if not mac_ids:
        return ok({"items": []})

    c = Counter()

    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        for day in daterange(start, end):
            events = list(read_bucket(doc, "logs", day))
            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))

            for e in events:
                if not isinstance(e, dict):
                    continue
                key = e.get(by) or "(unknown)"
                c[str(key)] += 1

    items = [{"name": k, "count": v} for k, v in c.most_common(limit)]
    return ok({"items": items})


@insights_api.get("/api/insights/hourly")
@require_dashboard_access()
def hourly():
    """Hourly logs distribution (UTC) for the selected date range."""
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)

    start, end, from_s, to_s = get_range_from_request()

    labels = [f"{h:02d}" for h in range(24)]
    buckets = [0 for _ in range(24)]

    if not mac_ids:
        return ok({"labels": labels, "series": [{"name": "Logs", "data": buckets}]})

    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        for day in daterange(start, end):
            events = list(read_bucket(doc, "logs", day))
            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))

            for e in events:
                if not isinstance(e, dict):
                    continue
                ts = e.get("ts") or ""
                # ISO like 2026-01-25T12:34:56Z -> hour at positions 11..13
                try:
                    hour = int(ts[11:13])
                    if 0 <= hour <= 23:
                        buckets[hour] += 1
                except Exception:
                    pass

    return ok({"labels": labels, "series": [{"name": "Logs", "data": buckets}]})
