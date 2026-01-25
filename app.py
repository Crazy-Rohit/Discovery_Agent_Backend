from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import secrets
import re

from config import CORS_ORIGINS, DEBUG, HOST, PORT
from db import ensure_indexes, users
from auth import (
    verify_password,
    issue_token,
    get_user_public,
    hash_password,
    jwt_verify,
)

from rbac import ROLE_C_SUITE, ROLE_DEPT_HEAD, ROLE_TEAM_MEMBER, scope_filter_for_logs

import users_api
import departments_api
import ingest
import data_api
import insights

app = Flask(__name__)

# -----------------------------
# CORS (Fix for browser "Network Error")
# -----------------------------
# Allow your Vite dev server origins explicitly.
# If CORS_ORIGINS="*" we allow everything (dev mode).
if CORS_ORIGINS == "*" or CORS_ORIGINS == ["*"]:
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
else:
    CORS(
        app,
        resources={r"/api/*": {"origins": CORS_ORIGINS}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )


def ok(data=None, status=200):
    return jsonify({"ok": True, "data": data}), status


def err(msg, status=400):
    return jsonify({"ok": False, "error": msg}), status


@app.errorhandler(404)
def not_found(_):
    return err("not found", 404)


@app.errorhandler(500)
def server_error(_e):
    return err("internal server error", 500)


def find_user_by_email(email_in: str):
    email_in = (email_in or "").strip()
    if not email_in:
        return None, ""

    email_norm = email_in.lower()

    u = users.find_one({"company_username_norm": email_norm})
    if u:
        return u, email_norm

    u = users.find_one({"company_username": email_norm})
    if u:
        return u, email_norm

    # fallback: case-insensitive
    u = users.find_one({"company_username": {"$regex": f"^{re.escape(email_in)}$", "$options": "i"}})
    return u, email_norm


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    try:
        payload = jwt_verify(token)
        user_id = payload.get("sub")
        u = get_user_public(user_id)
        if not u or not u.get("is_active", True):
            return None
        return u
    except Exception:
        return None


def require_auth():
    return current_user()


def require_c_suite(u):
    return u.get("role_key") == ROLE_C_SUITE or u.get("role") == ROLE_C_SUITE


@app.get("/api/health")
def health():
    return ok({"status": "up"})


# ---------------- AUTH ----------------

@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}

    user_mac_id = (body.get("user_mac_id") or "").strip()
    email_in = (body.get("email") or body.get("company_username") or "").strip()
    password = body.get("password") or ""

    full_name = (body.get("full_name") or body.get("name") or "").strip()
    contact_no = (body.get("contact_no") or "").strip()

    role_key = (body.get("role_key") or ROLE_TEAM_MEMBER).strip().upper()
    department = (body.get("department") or "").strip()
    pc_username = (body.get("pc_username") or "").strip()

    license_accepted = bool(body.get("license_accepted", True))
    license_version = (body.get("license_version") or "1.0").strip()

    if not email_in or not password:
        return err("company_username (email) and password are required", 400)

    user, email_norm = find_user_by_email(email_in)

    if role_key == "C_SUITE":
        department = ""  # not required
    elif not department:
        return err("department is required for DEPARTMENT_HEAD/DEPARTMENT_MEMBER", 400)

    now = datetime.utcnow()
    pw_hash, pw_salt, pw_iter = hash_password(password)

    if user:
        users.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "company_username": email_norm,
                "company_username_norm": email_norm,
                "full_name": full_name or user.get("full_name"),
                "contact_no": contact_no or user.get("contact_no"),
                "department": department or user.get("department"),
                "role_key": role_key or user.get("role_key", ROLE_TEAM_MEMBER),
                "license_accepted": license_accepted,
                "license_accepted_at": now if license_accepted else user.get("license_accepted_at"),
                "license_version": license_version,
                "is_active": True,
                "password_hash": pw_hash,
                "password_salt": pw_salt,
                "password_iter": pw_iter,
                "password_updated_at": now,
                "last_seen_at": now,
            }}
        )
        return ok({"message": "Account activated. Please login with email and password."}, 200)

    if not user_mac_id:
        user_mac_id = f"PORTAL-{secrets.token_hex(6).upper()}"
    if not pc_username:
        pc_username = "PORTAL"

    doc = {
        "company_username": email_norm,
        "company_username_norm": email_norm,
        "full_name": full_name or None,
        "contact_no": contact_no or None,
        "department": department or None,
        "role_key": role_key,
        "pc_username": pc_username,
        "created_at": now,
        "last_seen_at": now,
        "license_accepted": license_accepted,
        "license_accepted_at": now if license_accepted else None,
        "license_version": license_version,
        "is_active": True,
        "password_hash": pw_hash,
        "password_salt": pw_salt,
        "password_iter": pw_iter,
        "password_updated_at": now,
    }

    users.insert_one(doc)
    return ok({"message": "Registration successful. Please login with email and password."}, 201)


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email_in = (body.get("email") or body.get("company_username") or "").strip()
    password = body.get("password") or ""

    if not email_in or not password:
        return err("email and password required", 400)

    user, email_norm = find_user_by_email(email_in)
    if not user or not user.get("is_active", True):
        return err("invalid credentials", 401)

    if not verify_password(
        password,
        user.get("password_hash"),
        user.get("password_salt"),
        user.get("password_iter"),
    ):
        return err("invalid credentials", 401)

    users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_seen_at": datetime.utcnow(), "company_username": email_norm, "company_username_norm": email_norm}},
    )

    token = issue_token(str(user["_id"]), user.get("role_key", ROLE_TEAM_MEMBER))
    profile = get_user_public(str(user["_id"]))
    return ok({"token": token, "profile": profile})


@app.get("/api/auth/me")
def me():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    return ok(u)


@app.post("/api/auth/forgot-password")
def forgot_password():
    body = request.get_json(silent=True) or {}

    email_in = (body.get("email") or body.get("company_username") or "").strip()
    new_password = (body.get("new_password") or "").strip()

    if not email_in:
        return err("email is required", 400)
    if not new_password or len(new_password) < 4:
        return err("new_password must be at least 4 characters", 400)

    user, _email_norm = find_user_by_email(email_in)
    if not user:
        return err("user not found", 404)

    pw_hash, pw_salt, pw_iter = hash_password(new_password)

    users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password_hash": pw_hash,
            "password_salt": pw_salt,
            "password_iter": pw_iter,
            "password_updated_at": datetime.utcnow(),
        }}
    )
    return ok({"message": "Password updated successfully"})


# -----------------------------
# Start
# -----------------------------
if __name__ == "__main__":
    try:
        ensure_indexes()
    except Exception:
        pass

    app.run(host=HOST, port=PORT, debug=DEBUG)
