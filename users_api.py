from datetime import datetime
import re
from flask import request

from db import users
from auth import hash_password

def _email_ok(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))

def list_users(current_user: dict):
    # C-suite can see all; others might be filtered in your RBAC layer later
    out = []
    for u in users.find({}, {"password_hash": 0, "reset_token": 0}):
        out.append({
            "_id": str(u.get("_id")),
            "user_mac_id": u.get("user_mac_id") or str(u.get("_id")),
            "company_username": u.get("company_username"),
            "pc_username": u.get("pc_username"),
            "department": u.get("department"),
            "role_key": u.get("role_key", "DEPARTMENT_MEMBER"),
            "license_accepted": bool(u.get("license_accepted", False)),
            "license_version": u.get("license_version", "1.0"),
            "created_at": u.get("created_at"),
            "last_seen_at": u.get("last_seen_at"),
            "is_active": bool(u.get("is_active", True)),
        })
    return out

def create_user():
    body = request.get_json(silent=True) or {}

    user_mac_id = (body.get("user_mac_id") or "").strip()
    company_username = (body.get("company_username") or "").strip().lower()
    password = body.get("password") or ""

    department = (body.get("department") or "").strip()
    pc_username = (body.get("pc_username") or "").strip()
    role_key = (body.get("role_key") or "DEPARTMENT_MEMBER").strip()

    license_accepted = bool(body.get("license_accepted", False))
    license_version = (body.get("license_version") or "1.0").strip()

    if not user_mac_id or not company_username or not password:
        raise ValueError("user_mac_id, company_username (email) and password are required")

    if not _email_ok(company_username):
        raise ValueError("invalid email format")

    if users.find_one({"company_username": company_username}):
        raise ValueError("email already registered")

    if users.find_one({"_id": user_mac_id}):
        raise ValueError("device (mac) already registered")

    now = datetime.utcnow()

    doc = {
        "_id": user_mac_id,
        "user_mac_id": user_mac_id,
        "company_username": company_username,
        "department": department,
        "pc_username": pc_username,
        "role_key": role_key,
        "license_accepted": license_accepted,
        "license_accepted_at": now if license_accepted else None,
        "license_version": license_version,
        "created_at": now,
        "last_seen_at": now,
        "is_active": True,
        "password_hash": hash_password(password),
    }

    users.insert_one(doc)
    return {"user_mac_id": user_mac_id, "company_username": company_username}

def update_user(company_username: str):
    # company_username is used as identifier (email)
    company_username = (company_username or "").strip().lower()
    body = request.get_json(silent=True) or {}

    u = users.find_one({"company_username": company_username})
    if not u:
        raise KeyError("user not found")

    update = {}

    # Allow updating selected fields
    for key in ["department", "pc_username", "role_key", "is_active", "license_version"]:
        if key in body:
            update[key] = body[key]

    # Accept license changes
    if "license_accepted" in body:
        update["license_accepted"] = bool(body["license_accepted"])
        update["license_accepted_at"] = datetime.utcnow() if update["license_accepted"] else None

    # Password reset/update
    if "password" in body and body["password"]:
        update["password_hash"] = hash_password(body["password"])

    if not update:
        return

    users.update_one({"_id": u["_id"]}, {"$set": update})
