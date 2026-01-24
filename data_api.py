from typing import Dict, Any, List
from datetime import datetime

from db import logs as col_logs
from rbac import scope_filter_for_logs


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

    days = []
    cur = start
    while cur.date() <= end.date():
        days.append(cur.strftime("%Y-%m-%d"))
        cur = cur.replace(day=cur.day + 1)
    return days


# =========================
# LOGS
# =========================
def list_logs(current_user: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns flattened logs respecting RBAC:
      - C_SUITE: all logs
      - DEPARTMENT_HEAD: department logs
      - MEMBER: only their logs
    """
    base_q = scope_filter_for_logs(current_user)

    from_day = params.get("from")
    to_day = params.get("to")
    days = _iter_day_range(from_day, to_day)

    page = max(int(params.get("page", 1)), 1)
    limit = max(min(int(params.get("limit", 50)), 200), 1)
    skip = (page - 1) * limit

    rows: List[Dict[str, Any]] = []

    for doc in col_logs.find(base_q):
        company_username = doc.get("company_username")
        department = doc.get("department")
        mac = doc.get("user_mac_id")

        logs_obj = doc.get("logs") or {}
        for day in days:
            for rec in logs_obj.get(day, []):
                rows.append({
                    "ts": rec.get("ts"),
                    "company_username": company_username,
                    "department": department,
                    "user_mac_id": mac,
                    "application": rec.get("application"),
                    "category": rec.get("category"),
                    "operation": rec.get("operation"),
                    "detail": rec.get("detail"),
                })

    # sort newest first
    rows.sort(key=lambda x: x.get("ts") or "", reverse=True)

    total = len(rows)
    items = rows[skip: skip + limit]

    return {
        "items": items,
        "page": page,
        "limit": limit,
        "total": total,
    }


# =========================
# SCREENSHOTS
# =========================
def list_screenshots(current_user: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns flattened screenshots respecting RBAC.
    """
    base_q = scope_filter_for_logs(current_user)

    from_day = params.get("from")
    to_day = params.get("to")
    days = _iter_day_range(from_day, to_day)

    page = max(int(params.get("page", 1)), 1)
    limit = max(min(int(params.get("limit", 50)), 200), 1)
    skip = (page - 1) * limit

    rows: List[Dict[str, Any]] = []

    for doc in col_logs.find(base_q):
        company_username = doc.get("company_username")
        department = doc.get("department")
        mac = doc.get("user_mac_id")

        ss_obj = doc.get("screenshots") or {}
        for day in days:
            for rec in ss_obj.get(day, []):
                rows.append({
                    "ts": rec.get("ts"),
                    "company_username": company_username,
                    "department": department,
                    "user_mac_id": mac,
                    "application": rec.get("application"),
                    "path": rec.get("path"),
                    "caption": rec.get("caption"),
                })

    rows.sort(key=lambda x: x.get("ts") or "", reverse=True)

    total = len(rows)
    items = rows[skip: skip + limit]

    return {
        "items": items,
        "page": page,
        "limit": limit,
        "total": total,
    }
