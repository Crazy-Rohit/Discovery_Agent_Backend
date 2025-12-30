from typing import Dict, Any, List, Set, Tuple
from datetime import datetime, timezone, date, timedelta
from flask import request
from db import logs as col_logs

APP_TZ = timezone.utc

def parse_yyyy_mm_dd(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def daterange_days(d1: date, d2: date) -> List[str]:
    if d2 < d1:
        d1, d2 = d2, d1
    out = []
    cur = d1
    while cur <= d2:
        out.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return out

def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(APP_TZ)
    except Exception:
        return None

def get_days_from_query() -> Tuple[List[str], str, str]:
    today = datetime.now(APP_TZ).date().strftime("%Y-%m-%d")
    f_from = request.args.get("from") or today
    f_to = request.args.get("to") or f_from
    days = daterange_days(parse_yyyy_mm_dd(f_from), parse_yyyy_mm_dd(f_to))
    return days, f_from, f_to

def iter_records(docs: List[Dict[str, Any]], days: List[str], kind: str):
    for d in docs:
        base = {
            "user_mac_id": d.get("user_mac_id"),
            "username": d.get("username"),
            "department": d.get("department"),
        }
        obj = d.get(kind) or {}
        for day in days:
            for item in (obj.get(day) or []):
                yield {**base, "day": day, **item}

def summary(q: Dict[str, Any]) -> Dict[str, Any]:
    days, f_from, f_to = get_days_from_query()
    docs = list(col_logs.find(q, {"_id": 0, "user_mac_id": 1, "username": 1, "department": 1, "logs": 1, "screenshots": 1}))

    total_logs = 0
    total_screenshots = 0
    users: Set[str] = set()
    devices: Set[str] = set()
    top_app, top_cat, top_op = {}, {}, {}

    for d in docs:
        if d.get("username"): users.add(d["username"])
        if d.get("user_mac_id"): devices.add(d["user_mac_id"])

    for rec in iter_records(docs, days, "logs"):
        total_logs += 1
        a = (rec.get("application") or "unknown").strip() or "unknown"
        c = (rec.get("category") or "unknown").strip() or "unknown"
        o = (rec.get("operation") or "unknown").strip() or "unknown"
        top_app[a] = top_app.get(a, 0) + 1
        top_cat[c] = top_cat.get(c, 0) + 1
        top_op[o] = top_op.get(o, 0) + 1

    for _ in iter_records(docs, days, "screenshots"):
        total_screenshots += 1

    def top1(m):
        if not m: return {"name": None, "count": 0}
        k, v = max(m.items(), key=lambda x: x[1])
        return {"name": k, "count": v}

    return {
        "range": {"from": f_from, "to": f_to},
        "totals": {
            "logs": total_logs,
            "screenshots": total_screenshots,
            "unique_users": len(users),
            "unique_devices": len(devices),
        },
        "top": {
            "application": top1(top_app),
            "category": top1(top_cat),
            "operation": top1(top_op),
        }
    }

def top(q: Dict[str, Any]) -> Dict[str, Any]:
    days, f_from, f_to = get_days_from_query()
    metric = (request.args.get("metric") or "logs").strip().lower()
    by = (request.args.get("by") or "application").strip().lower()
    limit = max(1, min(int(request.args.get("limit") or 10), 50))

    allowed_by = {"application", "category", "operation", "username", "department", "device"}
    if metric not in {"logs", "screenshots"}:
        raise ValueError("invalid metric")
    if by not in allowed_by:
        raise ValueError("invalid by")

    docs = list(col_logs.find(q, {"_id": 0, "user_mac_id": 1, "username": 1, "department": 1, metric: 1}))
    counts: Dict[str, int] = {}

    for rec in iter_records(docs, days, metric):
        if by == "application":
            k = (rec.get("application") or "unknown").strip() or "unknown"
        elif by == "category":
            k = (rec.get("category") or "unknown").strip() or "unknown"
        elif by == "operation":
            k = (rec.get("operation") or "unknown").strip() or "unknown"
        elif by == "username":
            k = rec.get("username") or "unknown"
        elif by == "department":
            k = rec.get("department") or "unknown"
        else:
            k = rec.get("user_mac_id") or "unknown"
        counts[k] = counts.get(k, 0) + 1

    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return {"range": {"from": f_from, "to": f_to}, "metric": metric, "by": by,
            "items": [{"name": k, "count": v} for k, v in items]}

def timeseries(q: Dict[str, Any]) -> Dict[str, Any]:
    days, f_from, f_to = get_days_from_query()
    metric = (request.args.get("metric") or "logs").strip().lower()
    group_by = (request.args.get("group_by") or "all").strip().lower()

    if metric not in {"logs", "screenshots"}:
        raise ValueError("invalid metric")
    if group_by not in {"all", "user", "department", "device"}:
        raise ValueError("invalid group_by")

    docs = list(col_logs.find(q, {"_id": 0, "user_mac_id": 1, "username": 1, "department": 1, metric: 1}))

    series: Dict[str, Dict[str, int]] = {}
    if group_by == "all":
        series["all"] = {d: 0 for d in days}

    for rec in iter_records(docs, days, metric):
        day = rec.get("day")
        if group_by == "user":
            g = rec.get("username") or "unknown"
        elif group_by == "department":
            g = rec.get("department") or "unknown"
        elif group_by == "device":
            g = rec.get("user_mac_id") or "unknown"
        else:
            g = "all"

        if g not in series:
            series[g] = {d: 0 for d in days}
        series[g][day] += 1

    labels = days
    out = [{"name": name, "data": [m[d] for d in labels]} for name, m in series.items()]
    if group_by != "all":
        out.sort(key=lambda s: sum(s["data"]), reverse=True)

    return {"range": {"from": f_from, "to": f_to}, "metric": metric, "group_by": group_by,
            "labels": labels, "series": out}

def hourly(q: Dict[str, Any]) -> Dict[str, Any]:
    days, f_from, f_to = get_days_from_query()
    metric = (request.args.get("metric") or "logs").strip().lower()
    if metric not in {"logs", "screenshots"}:
        raise ValueError("invalid metric")

    docs = list(col_logs.find(q, {"_id": 0, "user_mac_id": 1, "username": 1, "department": 1, metric: 1}))
    hourly = {str(h): 0 for h in range(24)}

    for rec in iter_records(docs, days, metric):
        dt = parse_iso(str(rec.get("ts") or ""))
        if not dt:
            continue
        hourly[str(dt.hour)] += 1

    return {"range": {"from": f_from, "to": f_to}, "metric": metric, "hourly": hourly}
