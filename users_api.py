from datetime import datetime
import re
from flask import request

from db import users
from auth import hash_password


def _email_ok(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def list_users(current_user: dict):
    out = []

    projection = {
        "password_hash": 0,
        "password_salt": 0,
        "password_iter": 0,
        "password": 0,
        "password_type": 0,
        "reset_token": 0,
    }

    for u in users.find({}, projection):
        out.append({
            "_id": str(u.get("_id")),
            "user_mac_id": u.get("user_mac_id") or str(u.get("_id")),

            "company_username": u.get("company_username"),
            "company_username_norm": u.get("company_username_norm") or _norm_email(u.get("company_username")),

            "full_name": u.get("full_name") or u.get("name"),
            "contact_no": u.get("contact_no"),

            "pc_username": u.get("pc_username"),
            "department": u.get("department"),
            "role_key": u.get("role_key", "DEPARTMENT_MEMBER"),

            "license_accepted": bool(u.get("license_accepted", False)),
            "license_version": u.get("license_version", "1.0"),
            "license_accepted_at": u.get("license_accepted_at"),

            "created_at": u.get("created_at"),
            "last_seen_at": u.get("last_seen_at"),
            "is_active": bool(u.get("is_active", True)),
        })
    return out


def create_user():
    body = request.get_json(silent=True) or {}

    user_mac_id = (body.get("user_mac_id") or "").strip()
    company_username = _norm_email(body.get("company_username"))
    password = body.get("password") or ""

    department = (body.get("department") or "").strip()
    pc_username = (body.get("pc_username") or "").strip()
    role_key = (body.get("role_key") or "DEPARTMENT_MEMBER").strip().upper()

    full_name = (body.get("full_name") or body.get("name") or "").strip()
    contact_no = (body.get("contact_no") or "").strip()

    license_accepted = bool(body.get("license_accepted", False))
    license_version = (body.get("license_version") or "1.0").strip()

    if not user_mac_id or not company_username or not password:
        raise ValueError("user_mac_id, company_username (email) and password are required")

    if not _email_ok(company_username):
        raise ValueError("invalid email format")

    if users.find_one({"company_username_norm": company_username}) or users.find_one({"company_username": company_username}):
        raise ValueError("email already registered")

    if users.find_one({"_id": user_mac_id}):
        raise ValueError("device (mac) already registered")

    now = datetime.utcnow()
    pw_hash, pw_salt, pw_iter = hash_password(password)

    doc = {
        "_id": user_mac_id,
        "user_mac_id": user_mac_id,
        "company_username": company_username,
        "company_username_norm": company_username,

        "full_name": full_name or None,
        "contact_no": contact_no or None,

        "department": department,
        "pc_username": pc_username,
        "role_key": role_key,

        "license_accepted": license_accepted,
        "license_accepted_at": now if license_accepted else None,
        "license_version": license_version,

        "created_at": now,
        "last_seen_at": now,
        "is_active": True,

        "password_hash": pw_hash,
        "password_salt": pw_salt,
        "password_iter": pw_iter,
        "password_updated_at": now,
    }

    users.insert_one(doc)
    return {"user_mac_id": user_mac_id, "company_username": company_username}


def update_user(company_username: str):
    company_username = _norm_email(company_username)
    body = request.get_json(silent=True) or {}

    u = users.find_one({"company_username_norm": company_username})
    if not u:
        u = users.find_one({"company_username": company_username})
    if not u:
        raise KeyError("user not found")

    update = {}
    unset = {}

    for key in ["department", "pc_username", "role_key", "is_active", "license_version"]:
        if key in body:
            if key == "role_key" and body[key]:
                update[key] = str(body[key]).strip().upper()
            else:
                update[key] = body[key]

    if "full_name" in body:
        update["full_name"] = (body.get("full_name") or "").strip() or None
    if "name" in body and "full_name" not in update:
        update["full_name"] = (body.get("name") or "").strip() or None
    if "contact_no" in body:
        update["contact_no"] = (body.get("contact_no") or "").strip() or None

    if "license_accepted" in body:
        update["license_accepted"] = bool(body["license_accepted"])
        update["license_accepted_at"] = datetime.utcnow() if update["license_accepted"] else None

    if "password" in body and body["password"]:
        pw_hash, pw_salt, pw_iter = hash_password(body["password"])
        update["password_hash"] = pw_hash
        update["password_salt"] = pw_salt
        update["password_iter"] = pw_iter
        update["password_updated_at"] = datetime.utcnow()

        unset["password"] = ""
        unset["password_type"] = ""

    if "company_username" in body and body["company_username"]:
        new_email = _norm_email(body["company_username"])
        if not _email_ok(new_email):
            raise ValueError("invalid email format")
        update["company_username"] = new_email
        update["company_username_norm"] = new_email

    if not update and not unset:
        return

    ops = {}
    if update:
        ops["$set"] = update
    if unset:
        ops["$unset"] = unset

    users.update_one({"_id": u["_id"]}, ops)
