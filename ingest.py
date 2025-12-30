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

def normalize_user_mac(username: str, mac_id: str) -> str:
    mac_id = mac_id.strip().replace(":", "").replace("-", "")
    return f"{username.strip()}__{mac_id}"

def ingest_log_payload() -> Dict[str, Any]:
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    mac_id = (body.get("mac_id") or "").strip()
    if not username or not mac_id:
        raise ValueError("username and mac_id required")

    user_doc = col_users.find_one({"username": username}, {"department": 1})
    if not user_doc:
        raise ValueError("unknown username")

    department = user_doc.get("department")
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

    user_mac_id = normalize_user_mac(username, mac_id)
    col_logs.update_one(
        {"user_mac_id": user_mac_id},
        {
            "$setOnInsert": {
                "user_mac_id": user_mac_id,
                "username": username,
                "department": department,
                "created_at": now_iso(),
            },
            "$set": {"username": username, "department": department, "updated_at": now_iso()},
            "$push": {f"logs.{day_key}": log_rec},
        },
        upsert=True,
    )
    return {"ingested": True, "user_mac_id": user_mac_id, "day": day_key}

def ingest_screenshot_payload() -> Dict[str, Any]:
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    mac_id = (body.get("mac_id") or "").strip()
    path = (body.get("path") or "").strip()
    if not username or not mac_id or not path:
        raise ValueError("username, mac_id, path required")

    user_doc = col_users.find_one({"username": username}, {"department": 1})
    if not user_doc:
        raise ValueError("unknown username")

    department = user_doc.get("department")
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

    user_mac_id = normalize_user_mac(username, mac_id)
    col_logs.update_one(
        {"user_mac_id": user_mac_id},
        {
            "$setOnInsert": {
                "user_mac_id": user_mac_id,
                "username": username,
                "department": department,
                "created_at": now_iso(),
            },
            "$set": {"username": username, "department": department, "updated_at": now_iso()},
            "$push": {f"screenshots.{day_key}": ss_rec},
        },
        upsert=True,
    )
    return {"ingested": True, "user_mac_id": user_mac_id, "day": day_key}
