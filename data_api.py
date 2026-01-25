from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from bson import ObjectId

from db import (
    ensure_indexes,
    users,
    logs,
    screenshots,
)

from rbac import require_dashboard_access

data_api = Blueprint("data_api", __name__)


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


def user_map(mac_ids):
    if not mac_ids:
        return {}

    docs = users.find(
        {"_id": {"$in": mac_ids}},
        {
            "_id": 1,
            "company_username": 1,
            "full_name": 1,
            "department": 1,
            "role_key": 1,
        },
    )
    return {u["_id"]: u for u in docs}


def read_bucket(doc, key, day):
    return (doc.get(key) or {}).get(day, []) or []


def read_archives(col, mac_id, key, day):
    prefix = f"{mac_id}|archive|{key}|{day}|"
    return col.find({"_id": {"$regex": f"^{prefix}"}})


# -------------------------
# Init indexes once
# -------------------------
@data_api.before_app_request
def _init_indexes():
    try:
        ensure_indexes()
    except Exception:
        pass


# -------------------------
# APIs
# -------------------------
@data_api.get("/api/users")
@require_dashboard_access()
def list_users():
    identity = getattr(__import__("flask").g, "identity", {})
    mac_ids = get_allowed_mac_ids(identity)
    umap = user_map(mac_ids)

    out = []
    for mac, u in umap.items():
        out.append(
            {
                "mac_id": mac,
                "company_username": u.get("company_username"),
                "full_name": u.get("full_name"),
                "department": u.get("department"),
                "role_key": u.get("role_key"),
            }
        )

    return jsonify({"ok": True, "users": out})


@data_api.get("/api/logs")
@require_dashboard_access()
def get_logs():
    identity = getattr(__import__("flask").g, "identity", {})
    mac_ids = get_allowed_mac_ids(identity)
    if not mac_ids:
        return jsonify({"ok": True, "logs": []})

    start = parse_date(request.args.get("start"))
    end = parse_date(request.args.get("end"))

    if not start and not end:
        start = end = datetime.utcnow()
    elif start and not end:
        end = start
    elif end and not start:
        start = end

    umap = user_map(mac_ids)
    out = []

    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc["_id"]
        u = umap.get(mac, {})
        for day in daterange(start, end):
            events = read_bucket(doc, "logs", day)

            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))

            for e in events:
                out.append(
                    {
                        "mac_id": mac,
                        "day": day,
                        "event": e,
                        "company_username": u.get("company_username"),
                        "full_name": u.get("full_name"),
                        "department": u.get("department"),
                        "role_key": u.get("role_key"),
                    }
                )

    out.sort(key=lambda x: x["event"].get("ts", ""), reverse=True)
    return jsonify({"ok": True, "logs": out})


@data_api.get("/api/screenshots")
@require_dashboard_access()
def get_screenshots():
    identity = getattr(__import__("flask").g, "identity", {})
    mac_ids = get_allowed_mac_ids(identity)
    if not mac_ids:
        return jsonify({"ok": True, "screenshots": []})

    start = parse_date(request.args.get("start"))
    end = parse_date(request.args.get("end"))

    if not start and not end:
        start = end = datetime.utcnow()
    elif start and not end:
        end = start
    elif end and not start:
        start = end

    umap = user_map(mac_ids)
    out = []

    for doc in screenshots.find({"_id": {"$in": mac_ids}}):
        mac = doc["_id"]
        u = umap.get(mac, {})
        for day in daterange(start, end):
            shots = read_bucket(doc, "screenshots", day)

            for a in read_archives(screenshots, mac, "screenshots", day):
                shots.extend(read_bucket(a, "screenshots", day))

            for s in shots:
                out.append(
                    {
                        "mac_id": mac,
                        "day": day,
                        "screenshot": s,
                        "company_username": u.get("company_username"),
                        "full_name": u.get("full_name"),
                        "department": u.get("department"),
                        "role_key": u.get("role_key"),
                    }
                )

    out.sort(key=lambda x: x["screenshot"].get("ts", ""), reverse=True)
    return jsonify({"ok": True, "screenshots": out})
