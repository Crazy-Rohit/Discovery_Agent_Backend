from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import secrets
import re

from config import CORS_ORIGINS, DEBUG, HOST, PORT
from db import ensure_indexes, users
from auth import verify_password, issue_token, get_user_public, hash_password, jwt_verify
from rbac import ROLE_C_SUITE, ROLE_DEPT_HEAD, ROLE_TEAM_MEMBER

import users_api
import departments_api
import ingest
import data_api
import insights

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS}})

def ok(data=None, status=200):
    return jsonify({"ok": True, "data": data}), status

def err(msg, status=400):
    return jsonify({"ok": False, "error": msg}), status

@app.errorhandler(404)
def not_found(_):
    return err("not found", 404)

@app.errorhandler(500)
def server_error(e):
    return err("internal server error", 500)

def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    try:
        payload = jwt_verify(token)
        user_mac_id = payload.get("sub")
        u = get_user_public(user_mac_id)
        if not u or not u.get("is_active", True):
            return None
        return u
    except Exception:
        return None

def require_auth():
    u = current_user()
    if not u:
        return None
    return u

def require_c_suite(u):
    # support your RBAC keys
    return u.get("role_key") == ROLE_C_SUITE or u.get("role") == ROLE_C_SUITE

@app.get("/api/health")
def health():
    return ok({"status": "up"})

# ---------------- AUTH ----------------

@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}

    user_mac_id = (body.get("user_mac_id") or "").strip()
    company_username = (body.get("company_username") or "").strip().lower()  # email
    password = body.get("password") or ""

    department = (body.get("department") or "").strip()
    pc_username = (body.get("pc_username") or "").strip()
    role_key = (body.get("role_key") or ROLE_TEAM_MEMBER).strip()

    license_accepted = bool(body.get("license_accepted", False))
    license_version = (body.get("license_version") or "1.0").strip()

    if not user_mac_id or not company_username or not password:
        return err("user_mac_id, company_username (email) and password are required", 400)

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", company_username):
        return err("invalid email format", 400)

    # Duplicate email check
    if users.find_one({"company_username": company_username}):
        return err("email already registered", 409)

    # Duplicate MAC check
    if users.find_one({"_id": user_mac_id}):
        return err("device (mac) already registered", 409)

    now = datetime.utcnow()

    doc = {
        "_id": user_mac_id,
        "user_mac_id": user_mac_id,
        "company_username": company_username,

        "created_at": now,
        "last_seen_at": now,

        "department": department,
        "pc_username": pc_username,
        "role_key": role_key,

        "license_accepted": license_accepted,
        "license_accepted_at": now if license_accepted else None,
        "license_version": license_version,

        "is_active": True,

        # required for login
        "password_hash": hash_password(password),
    }

    users.insert_one(doc)
    return ok({"message": "Registration successful. Please login with email and password."}, 201)

@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return err("email and password required", 400)

    user = users.find_one({"company_username": email})
    if not user or not user.get("is_active", True):
        return err("invalid credentials", 401)

    if not verify_password(password, user.get("password_hash", "")):
        return err("invalid credentials", 401)

    users.update_one({"_id": user["_id"]}, {"$set": {"last_seen_at": datetime.utcnow()}})

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
    email = (body.get("email") or "").strip().lower()
    if not email:
        return err("email required", 400)

    user = users.find_one({"company_username": email})
    if not user:
        return ok({"message": "If the account exists, reset instructions were initiated."})

    token = secrets.token_urlsafe(32)
    users.update_one({"_id": user["_id"]}, {"$set": {"reset_token": token}})

    if DEBUG:
        print(f"[RESET] company_username={user.get('company_username')} token={token}")

    return ok({"message": "If the account exists, reset instructions were initiated."})

# ---------------- Departments ----------------
@app.get("/api/departments")
def list_departments():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    return ok({"departments": departments_api.list_departments()})

@app.post("/api/departments")
def create_department():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    if not require_c_suite(u):
        return err("forbidden", 403)
    try:
        name = departments_api.create_department()
        return ok({"created": name}, 201)
    except Exception as e:
        return err(str(e), 400)

# ---------------- Users ----------------
@app.get("/api/users")
def list_users():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    return ok({"users": users_api.list_users(u)})

@app.post("/api/users")
def create_user():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    if not require_c_suite(u):
        return err("forbidden", 403)
    try:
        created = users_api.create_user()
        return ok({"created": created}, 201)
    except Exception as e:
        return err(str(e), 400)

@app.patch("/api/users/<company_username>")
def patch_user(company_username: str):
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    if not require_c_suite(u):
        return err("forbidden", 403)
    try:
        users_api.update_user(company_username)
        return ok({"updated": company_username})
    except KeyError:
        return err("user not found", 404)
    except Exception as e:
        return err(str(e), 400)

# ---------------- Ingest ----------------
@app.post("/api/ingest/log")
def ingest_log():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    try:
        data = ingest.ingest_log_payload()
        return ok(data, 201)
    except Exception as e:
        return err(str(e), 400)

@app.post("/api/ingest/screenshot")
def ingest_screenshot():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    try:
        data = ingest.ingest_screenshot_payload()
        return ok(data, 201)
    except Exception as e:
        return err(str(e), 400)

# ---------------- Data tables ----------------
@app.get("/api/logs")
def logs_table():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    try:
        return ok(data_api.get_logs(u))
    except PermissionError as e:
        return err(str(e), 403)
    except Exception as e:
        return err(str(e), 400)

@app.get("/api/screenshots")
def screenshots_table():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    try:
        return ok(data_api.get_screenshots(u))
    except PermissionError as e:
        return err(str(e), 403)
    except Exception as e:
        return err(str(e), 400)

# ---------------- Insights ----------------
@app.get("/api/insights/summary")
def insights_summary():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)

    from rbac import scope_filter_for_logs, is_user_visible_to, is_dept_visible_to
    q = scope_filter_for_logs(u)

    username = (request.args.get("username") or "").strip()
    dept = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()

    if username:
        if not is_user_visible_to(u, username):
            return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept):
            return err("forbidden department scope", 403)
        q["department"] = dept
    if device:
        q["user_mac_id"] = device

    return ok(insights.summary(q))

@app.get("/api/insights/top")
def insights_top():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)

    from rbac import scope_filter_for_logs, is_user_visible_to, is_dept_visible_to
    q = scope_filter_for_logs(u)

    username = (request.args.get("username") or "").strip()
    dept = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()

    if username:
        if not is_user_visible_to(u, username):
            return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept):
            return err("forbidden department scope", 403)
        q["department"] = dept
    if device:
        q["user_mac_id"] = device

    try:
        return ok(insights.top(q))
    except Exception as e:
        return err(str(e), 400)

@app.get("/api/insights/timeseries")
def insights_timeseries():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)

    from rbac import scope_filter_for_logs, is_user_visible_to, is_dept_visible_to
    q = scope_filter_for_logs(u)

    username = (request.args.get("username") or "").strip()
    dept = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()

    if username:
        if not is_user_visible_to(u, username):
            return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept):
            return err("forbidden department scope", 403)
        q["department"] = dept
    if device:
        q["user_mac_id"] = device

    try:
        return ok(insights.timeseries(q))
    except Exception as e:
        return err(str(e), 400)

@app.get("/api/insights/hourly")
def insights_hourly():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)

    from rbac import scope_filter_for_logs, is_user_visible_to, is_dept_visible_to
    q = scope_filter_for_logs(u)

    username = (request.args.get("username") or "").strip()
    dept = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()

    if username:
        if not is_user_visible_to(u, username):
            return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept):
            return err("forbidden department scope", 403)
        q["department"] = dept
    if device:
        q["user_mac_id"] = device

    try:
        return ok(insights.hourly(q))
    except Exception as e:
        return err(str(e), 400)

def bootstrap_admin_if_missing():
    if users.count_documents({}) == 0:
        now = datetime.utcnow()
        users.insert_one({
            "_id": "ADMIN-DEVICE",
            "user_mac_id": "ADMIN-DEVICE",
            "company_username": "admin@local",
            "pc_username": "ADMIN-PC",
            "department": "IT",
            "role_key": ROLE_C_SUITE,
            "license_accepted": True,
            "license_accepted_at": now,
            "license_version": "1.0",
            "created_at": now,
            "last_seen_at": now,
            "is_active": True,
            "password_hash": hash_password("admin123"),
        })
        print("[BOOT] Default admin created: admin@local / admin123 (CHANGE ASAP).")

if __name__ == "__main__":
    ensure_indexes()
    bootstrap_admin_if_missing()
    app.run(host=HOST, port=PORT, debug=DEBUG)
