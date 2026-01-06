from typing import Dict, Any, List
from datetime import datetime

from db import logs as col_logs


from datetime import datetime, timedelta

def _parse_date(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _iter_day_range(from_day: str, to_day: str):
    if not from_day or not to_day:
        return []

    start = _parse_date(from_day)
    end = _parse_date(to_day)
    if not start or not end:
        return []

    # If user accidentally sends inverted dates, swap safely
    if start.date() > end.date():
        start, end = end, start

    days = []
    cur = start
    while cur.date() <= end.date():
        days.append(cur.strftime("%Y-%m-%d"))
        cur = cur + timedelta(days=1)

    return days



# =========================
# SUMMARY
# =========================
def summary(base_q: Dict[str, Any], from_day: str, to_day: str) -> Dict[str, Any]:
    days = _iter_day_range(from_day, to_day)

    total_logs = 0
    total_screenshots = 0
    users = set()

    for doc in col_logs.find(base_q):
        users.add(doc.get("company_username"))

        logs_obj = doc.get("logs") or {}
        ss_obj = doc.get("screenshots") or {}

        for d in days:
            total_logs += len(logs_obj.get(d, []))
            total_screenshots += len(ss_obj.get(d, []))

    return {
        "range": {"from": from_day, "to": to_day},
        "totals": {
            "logs": total_logs,
            "screenshots": total_screenshots,
            "unique_users": len(users),
        },
    }


# =========================
# TOP (applications / categories)
# =========================
def top(base_q: Dict[str, Any], from_day: str, to_day: str, by: str, limit: int = 10):
    days = _iter_day_range(from_day, to_day)
    counter: Dict[str, int] = {}

    for doc in col_logs.find(base_q):
        logs_obj = doc.get("logs") or {}
        for d in days:
            for rec in logs_obj.get(d, []):
                key = rec.get(by)
                if not key:
                    continue
                counter[key] = counter.get(key, 0) + 1

    items = [{"name": k, "count": v} for k, v in counter.items()]
    items.sort(key=lambda x: x["count"], reverse=True)

    return {"items": items[:limit]}


# =========================
# TIMESERIES
# =========================
def timeseries(base_q: Dict[str, Any], from_day: str, to_day: str):
    days = _iter_day_range(from_day, to_day)
    counts = {d: 0 for d in days}

    for doc in col_logs.find(base_q):
        logs_obj = doc.get("logs") or {}
        for d in days:
            counts[d] += len(logs_obj.get(d, []))

    return {
        "labels": days,
        "series": [
            {
                "name": "Logs",
                "data": [counts[d] for d in days],
            }
        ],
    }


# =========================
# HOURLY HEATMAP
# =========================
def hourly(base_q: Dict[str, Any], from_day: str, to_day: str):
    days = _iter_day_range(from_day, to_day)
    hourly = {str(h): 0 for h in range(24)}

    for doc in col_logs.find(base_q):
        logs_obj = doc.get("logs") or {}
        for d in days:
            for rec in logs_obj.get(d, []):
                ts = rec.get("ts")
                if not ts:
                    continue
                try:
                    h = datetime.fromisoformat(ts.replace("Z", "")).hour
                    hourly[str(h)] += 1
                except Exception:
                    continue

    return {"hourly": hourly}
