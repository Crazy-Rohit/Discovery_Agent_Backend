from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from db import ensure_indexes, users, logs, screenshots
from rbac import require_dashboard_access

insights_api = Blueprint("insights_api", __name__)


# -------------------------
# Helpers
# -------------------------
def parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


def daterange(start, end):
    d = start
    while d <= end:
        yield d.strftime("%Y-%m-%d")
        d += timedelta(days=1)


def get_allowed_mac_ids(identity):
    role = identity.get("role_key")
    department = identity.get("department")

    if role == "C_SUITE":
        q = {}
        dep = request.args.get("department")
        if dep:
            q["department"] = dep
        return [u["_id"] for u in users.find(q, {"_id": 1})]

    if role == "DEPARTMENT_HEAD":
        if not department:
            return []
        return [u["_id"] for u in users.find({"department": department}, {"_id": 1})]

    return []


def read_bucket(doc, key, day):
    return (doc.get(key) or {}).get(day, []) or []


def read_archives(col, mac_id, key, day):
    prefix = f"{mac_id}|archive|{key}|{day}|"
    return col.find({"_id": {"$regex": f"^{prefix}"}})


# -------------------------
# Init indexes once
# -------------------------
@insights_api.before_app_request
def _init_indexes():
    try:
        ensure_indexes()
    except Exception:
        pass


# -------------------------
# APIs
# -------------------------
@insights_api.get("/api/insights/summary")
@require_dashboard_access()
def summary():
    """
    Summary scoped by role:
      - total users in scope
      - total logs in date range
      - total screenshots in date range

    Reads the plugin schema:
      logs: { logs: { 'YYYY-MM-DD': [events...] } }
      screenshots: { screenshots: { 'YYYY-MM-DD': [items...] } }
    """
    identity = getattr(__import__("flask").g, "identity", {})
    mac_ids = get_allowed_mac_ids(identity)

    if not mac_ids:
        return jsonify({"ok": True, "summary": {"users": 0, "logs": 0, "screenshots": 0}})

    start = parse_date(request.args.get("start"))
    end = parse_date(request.args.get("end"))

    if not start and not end:
        start = end = datetime.utcnow()
    elif start and not end:
        end = start
    elif end and not start:
        start = end

    total_logs = 0
    total_shots = 0

    # logs count
    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc["_id"]
        for day in daterange(start, end):
            events = read_bucket(doc, "logs", day)

            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))

            total_logs += len(events)

    # screenshots count
    for doc in screenshots.find({"_id": {"$in": mac_ids}}):
        mac = doc["_id"]
        for day in daterange(start, end):
            items = read_bucket(doc, "screenshots", day)

            for a in read_archives(screenshots, mac, "screenshots", day):
                items.extend(read_bucket(a, "screenshots", day))

            total_shots += len(items)

    return jsonify(
        {
            "ok": True,
            "summary": {
                "users": len(set(mac_ids)),
                "logs": total_logs,
                "screenshots": total_shots,
                "start": start.strftime("%Y-%m-%d"),
                "end": end.strftime("%Y-%m-%d"),
            },
        }
    )
