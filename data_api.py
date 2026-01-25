from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, request, g

from db import ensure_indexes, users, logs, screenshots
from rbac import require_dashboard_access, ROLE_C_SUITE, ROLE_DEPT_HEAD

data_api = Blueprint("data_api", __name__)


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


def get_range_from_request() -> Tuple[datetime, datetime]:
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

    return start, end


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


def user_map(mac_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not mac_ids:
        return {}
    docs = users.find(
        {"_id": {"$in": mac_ids}},
        {"_id": 1, "company_username": 1, "company_username_norm": 1, "full_name": 1, "department": 1, "role_key": 1},
    )
    out = {}
    for u in docs:
        out[u.get("_id")] = u
    return out


def read_bucket(doc: Dict[str, Any], key: str, day: str):
    return (doc.get(key) or {}).get(day, []) or []


def read_archives(col, mac_id: str, key: str, day: str):
    prefix = f"{mac_id}|archive|{key}|{day}|"
    return col.find({"_id": {"$regex": f"^{prefix}"}})


def paginate(items: List[Dict[str, Any]], page: int, limit: int):
    total = len(items)
    page = max(int(page or 1), 1)
    limit = max(min(int(limit or 100), 500), 1)
    start = (page - 1) * limit
    end = start + limit
    return {"items": items[start:end], "page": page, "limit": limit, "total": total}


@data_api.before_app_request
def _init_indexes():
    try:
        ensure_indexes()
    except Exception:
        pass


@data_api.get("/api/logs")
@require_dashboard_access()
def get_logs():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)

    page = int(request.args.get("page") or 1)
    limit = int(request.args.get("limit") or 100)

    if not mac_ids:
        return ok({"items": [], "page": page, "limit": limit, "total": 0})

    start, end = get_range_from_request()
    umap = user_map(mac_ids)
    out: List[Dict[str, Any]] = []

    for doc in logs.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        u = umap.get(mac, {})

        for day in daterange(start, end):
            events = list(read_bucket(doc, "logs", day))
            for a in read_archives(logs, mac, "logs", day):
                events.extend(read_bucket(a, "logs", day))

            for e in events:
                if not isinstance(e, dict):
                    continue

                out.append(
                    {
                        "ts": e.get("ts"),
                        "application": e.get("application"),
                        "category": e.get("category"),
                        "operation": e.get("operation"),

                        # ✅ NEW columns
                        "details": e.get("details") if e.get("details") is not None else e.get("detail"),
                        "window_title": e.get("window_title"),

                        # keep old key too (safe)
                        "detail": e.get("detail"),

                        "company_username": u.get("company_username_norm") or u.get("company_username"),
                        "full_name": u.get("full_name"),
                        "department": u.get("department"),
                        "role_key": u.get("role_key"),
                        "user_mac_id": mac,
                    }
                )

    out.sort(key=lambda x: x.get("ts") or "", reverse=True)
    return ok(paginate(out, page, limit))


@data_api.get("/api/screenshots")
@require_dashboard_access()
def get_screenshots():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)

    page = int(request.args.get("page") or 1)
    limit = int(request.args.get("limit") or 100)

    if not mac_ids:
        return ok({"items": [], "page": page, "limit": limit, "total": 0})

    start, end = get_range_from_request()
    umap = user_map(mac_ids)
    out: List[Dict[str, Any]] = []

    for doc in screenshots.find({"_id": {"$in": mac_ids}}):
        mac = doc.get("_id")
        u = umap.get(mac, {})

        for day in daterange(start, end):
            items = list(read_bucket(doc, "screenshots", day))
            for a in read_archives(screenshots, mac, "screenshots", day):
                items.extend(read_bucket(a, "screenshots", day))

            for s in items:
                if not isinstance(s, dict):
                    continue

                out.append(
                    {
                        "ts": s.get("ts"),
                        "application": s.get("application"),

                        # ✅ NEW columns
                        "window_title": s.get("window_title"),
                        "label": s.get("label"),
                        "file_path": s.get("file_path") or s.get("path"),
                        "screenshot_url": s.get("screenshot_url") or s.get("url") or s.get("path"),

                        "company_username": u.get("company_username_norm") or u.get("company_username"),
                        "full_name": u.get("full_name"),
                        "department": u.get("department"),
                        "role_key": u.get("role_key"),
                        "user_mac_id": s.get("user_mac_id") or mac,
                    }
                )

    out.sort(key=lambda x: x.get("ts") or "", reverse=True)
    return ok(paginate(out, page, limit))
