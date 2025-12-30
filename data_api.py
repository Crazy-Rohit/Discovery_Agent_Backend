import math
from flask import request
from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta

from db import logs as col_logs
from rbac import scope_filter_for_logs, is_user_visible_to, is_dept_visible_to

APP_TZ = timezone.utc

def parse_yyyy_mm_dd(s: str):
    return datetime.strptime(s, "%Y-%m-%d").date()

def daterange_days(d1, d2):
    if d2 < d1:
        d1, d2 = d2, d1
    out = []
    cur = d1
    while cur <= d2:
        out.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return out

def paginate(items: List[Dict[str, Any]], page: int, limit: int):
    limit = max(1, min(limit, 500))
    page = max(1, page)
    total = len(items)
    start = (page - 1) * limit
    end = start + limit
    pages = max(1, math.ceil(total / limit))
    return {"page": page, "limit": limit, "total": total, "pages": pages, "items": items[start:end]}

def iter_records(docs, days, kind):
    for d in docs:
        base = {"user_mac_id": d.get("user_mac_id"), "username": d.get("username"), "department": d.get("department")}
        obj = d.get(kind) or {}
        for day in days:
            for item in (obj.get(day) or []):
                yield {**base, "day": day, **item}

def get_logs(current):
    today = datetime.now(APP_TZ).date().strftime("%Y-%m-%d")
    f_from = request.args.get("from") or today
    f_to = request.args.get("to") or f_from
    days = daterange_days(parse_yyyy_mm_dd(f_from), parse_yyyy_mm_dd(f_to))

    username = (request.args.get("username") or "").strip()
    department = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()

    if username and not is_user_visible_to(current, username):
        raise PermissionError("forbidden username scope")
    if department and not is_dept_visible_to(current, department):
        raise PermissionError("forbidden department scope")

    q = scope_filter_for_logs(current)
    if username: q["username"] = username
    if department: q["department"] = department
    if device: q["user_mac_id"] = device

    app_f = (request.args.get("application") or "").strip().lower()
    cat_f = (request.args.get("category") or "").strip().lower()
    op_f = (request.args.get("operation") or "").strip().lower()

    page = int(request.args.get("page") or 1)
    limit = int(request.args.get("limit") or 50)

    docs = list(col_logs.find(q, {"_id": 0, "user_mac_id": 1, "username": 1, "department": 1, "logs": 1}))
    items = []
    for rec in iter_records(docs, days, "logs"):
        if app_f and app_f not in str(rec.get("application") or "").lower(): continue
        if cat_f and cat_f not in str(rec.get("category") or "").lower(): continue
        if op_f and op_f not in str(rec.get("operation") or "").lower(): continue
        items.append(rec)

    items.sort(key=lambda r: r.get("ts") or "", reverse=True)
    return paginate(items, page, limit)

def get_screenshots(current):
    today = datetime.now(APP_TZ).date().strftime("%Y-%m-%d")
    f_from = request.args.get("from") or today
    f_to = request.args.get("to") or f_from
    days = daterange_days(parse_yyyy_mm_dd(f_from), parse_yyyy_mm_dd(f_to))

    username = (request.args.get("username") or "").strip()
    department = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()

    if username and not is_user_visible_to(current, username):
        raise PermissionError("forbidden username scope")
    if department and not is_dept_visible_to(current, department):
        raise PermissionError("forbidden department scope")

    q = scope_filter_for_logs(current)
    if username: q["username"] = username
    if department: q["department"] = department
    if device: q["user_mac_id"] = device

    app_f = (request.args.get("application") or "").strip().lower()

    page = int(request.args.get("page") or 1)
    limit = int(request.args.get("limit") or 50)

    docs = list(col_logs.find(q, {"_id": 0, "user_mac_id": 1, "username": 1, "department": 1, "screenshots": 1}))
    items = []
    for rec in iter_records(docs, days, "screenshots"):
        if app_f and app_f not in str(rec.get("application") or "").lower(): continue
        items.append(rec)

    items.sort(key=lambda r: r.get("ts") or "", reverse=True)
    return paginate(items, page, limit)
