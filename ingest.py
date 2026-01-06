from datetime import datetime, timezone
from typing import Dict, Any
from flask import request
from db import logs as col_logs, users as col_users

APP_TZ = timezone.utc


def now_iso() -> str:
    return datetime.now(APP_TZ).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(APP_TZ)
    except Exception:
        return None


def normalize_mac(mac_id: str) -> str:
    """
    Normalize MAC into your DB format: 84-69-93-98-45-5D
    Accepts:
      - 84-69-93-98-45-5D
      - 84:69:93:98:45:5D
      - 84699398455D
    """
    s = (mac_id or "").strip().upper()
    if not s:
        return ""

    # Replace ":" with "-" if needed
    s = s.replace(":", "-")

    # If already in AA-BB-CC-DD-EE-FF form
    parts = s.split("-")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return "-".join(parts)

    # If it is raw hex (12 chars)
    raw = s.replace("-", "")
    if len(raw) == 12:
        return "-".join(raw[i:i+2] for i in range(0, 12, 2))

    # fallback (store as-is)
    return s


def _find_user(username: str) -> Dict[str, Any]:
    """Find user by company_username/company_username_norm."""
    username = (username or "").strip()
    if not username:
        return None

    u = col_users.find_one(
        {"company_username": username},
        {"department": 1, "role_key": 1, "full_name": 1, "contact_no": 1, "pc_username": 1, "company_username": 1, "company_username_norm": 1},
    )
    if not u:
        u = col_users.find_one(
            {"company_username_norm": username.lower()},
            {"department": 1, "role_key": 1, "full_name": 1, "contact_no": 1, "pc_username": 1, "company_username": 1, "company_username_norm": 1},
        )
    return u


def ingest_log_payload() -> Dict[str, Any]:
    body = request.get_json(silent=True) or {}

    username = (body.get("username") or "").strip()  # agent sends as "username" (email)
    mac_id = (body.get("mac_id") or "").strip()
    if not username or not mac_id:
        raise ValueError("username and mac_id required")

    user_doc = _find_user(username)
    if not user_doc:
        raise ValueError("unknown username")

    department = user_doc.get("department")
    role_key = user_doc.get("role_key")
    full_name = user_doc.get("full_name")
    contact_no = user_doc.get("contact_no")
    pc_username = user_doc.get("pc_username")

    ts = (body.get("ts") or now_iso()).strip()
    dt = parse_iso(ts) or datetime.now(APP_TZ)
    day_key = dt.date().strftime("%Y-%m-%d")

    log_rec = {
        "ts": ts,
        "application": body.get("application"),
        "category": body.get("category"),
        "operation": body.get("operation"),
        "detail": body.get("detail"),
        "meta": body.get("meta") or {},
    }

    mac = normalize_mac(mac_id)
    col_logs.update_one(
        {"_id": mac},
        {
            "$setOnInsert": {
                "_id": mac,
                "user_mac_id": mac,
                "created_at": now_iso(),
            },
            "$set": {
                "company_username": username.lower(),
                "department": department,
                "role_key": role_key,
                "full_name": full_name,
                "contact_no": contact_no,
                "pc_username": pc_username,
                "updated_at": now_iso(),
            },
            "$push": {f"logs.{day_key}": log_rec},
        },
        upsert=True,
    )

    return {"ingested": True, "user_mac_id": mac, "day": day_key}


def ingest_screenshot_payload() -> Dict[str, Any]:
    body = request.get_json(silent=True) or {}

    username = (body.get("username") or "").strip()
    mac_id = (body.get("mac_id") or "").strip()
    path = (body.get("path") or "").strip()
    if not username or not mac_id or not path:
        raise ValueError("username, mac_id, path required")

    user_doc = _find_user(username)
    if not user_doc:
        raise ValueError("unknown username")

    department = user_doc.get("department")
    role_key = user_doc.get("role_key")
    full_name = user_doc.get("full_name")
    contact_no = user_doc.get("contact_no")
    pc_username = user_doc.get("pc_username")

    ts = (body.get("ts") or now_iso()).strip()
    dt = parse_iso(ts) or datetime.now(APP_TZ)
    day_key = dt.date().strftime("%Y-%m-%d")

    ss_rec = {
        "ts": ts,
        "application": body.get("application"),
        "path": path,
        "caption": body.get("caption"),
        "meta": body.get("meta") or {},
    }

    mac = normalize_mac(mac_id)
    col_logs.update_one(
        {"_id": mac},
        {
            "$setOnInsert": {
                "_id": mac,
                "user_mac_id": mac,
                "created_at": now_iso(),
            },
            "$set": {
                "company_username": username.lower(),
                "department": department,
                "role_key": role_key,
                "full_name": full_name,
                "contact_no": contact_no,
                "pc_username": pc_username,
                "updated_at": now_iso(),
            },
            "$push": {f"screenshots.{day_key}": ss_rec},
        },
        upsert=True,
    )

    return {"ingested": True, "user_mac_id": mac, "day": day_key}
