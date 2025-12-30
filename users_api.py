from flask import request
from db import users
from auth import hash_password
from rbac import ROLE_C_SUITE, ROLE_DEPT_HEAD, ROLE_TEAM_MEMBER, VALID_ROLES

def list_users(current):
    role = current.get("role")
    q = {}
    if role == ROLE_DEPT_HEAD:
        q = {"department": current.get("department")}
    elif role == ROLE_TEAM_MEMBER:
        q = {"username": current.get("username")}
    return list(users.find(q, {"_id": 0, "password_hash": 0}).sort("username", 1))

def create_user():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = (body.get("role") or "").strip()
    department = (body.get("department") or "").strip()
    is_active = bool(body.get("is_active", True))

    if not username or not password or not role or not department:
        raise ValueError("username, password, role, department required")
    if role not in VALID_ROLES:
        raise ValueError("invalid role")

    doc = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "department": department,
        "is_active": is_active
    }
    users.insert_one(doc)
    doc.pop("password_hash", None)
    doc.pop("_id", None)
    return doc

def update_user(username: str):
    body = request.get_json(silent=True) or {}
    updates = {}

    if "is_active" in body:
        updates["is_active"] = bool(body["is_active"])
    if "password" in body and body["password"]:
        updates["password_hash"] = hash_password(body["password"])
    if "role" in body and body["role"]:
        r = str(body["role"]).strip()
        if r not in VALID_ROLES:
            raise ValueError("invalid role")
        updates["role"] = r
    if "department" in body and body["department"]:
        updates["department"] = str(body["department"]).strip()

    if not updates:
        raise ValueError("no valid fields to update")

    res = users.update_one({"username": username}, {"$set": updates})
    if res.matched_count == 0:
        raise KeyError("user not found")
    return True
