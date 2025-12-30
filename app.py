from flask import Flask, request, jsonify
from flask_cors import CORS

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

def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    try:
        payload = jwt_verify(token)
        username = payload.get("sub")
        u = get_user_public(username)
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
    return u.get("role") == ROLE_C_SUITE

@app.get("/api/health")
def health():
    return ok({"status": "up"})

# ---------- Auth ----------
@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return err("username and password required", 400)

    user = users.find_one({"username": username})
    if not user or not user.get("is_active", True):
        return err("invalid credentials", 401)
    if not verify_password(password, user.get("password_hash", "")):
        return err("invalid credentials", 401)

    token = issue_token(username)
    profile = {"username": user["username"], "role": user["role"], "department": user.get("department"), "is_active": True}
    return ok({"token": token, "profile": profile})

@app.get("/api/auth/me")
def me():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    return ok(u)

# ---------- Departments ----------
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

# ---------- Users ----------
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

@app.patch("/api/users/<username>")
def patch_user(username: str):
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    if not require_c_suite(u):
        return err("forbidden", 403)
    try:
        users_api.update_user(username)
        return ok({"updated": username})
    except KeyError:
        return err("user not found", 404)
    except Exception as e:
        return err(str(e), 400)

# ---------- Ingest ----------
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

# ---------- Data tables ----------
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

# ---------- Insights ----------
@app.get("/api/insights/summary")
def insights_summary():
    u = require_auth()
    if not u:
        return err("unauthorized", 401)
    # RBAC is enforced via query scope in frontend filters; safest is to use same approach as tables later.
    # For now: allow only scoped data by passing scope-filtered query via frontend restrictions.
    # If you want strict enforcement here too, we can wire scope checks same as data_api.
    from rbac import scope_filter_for_logs, is_user_visible_to, is_dept_visible_to
    q = scope_filter_for_logs(u)

    username = (request.args.get("username") or "").strip()
    dept = (request.args.get("department") or "").strip()
    device = (request.args.get("device") or "").strip()
    if username:
        if not is_user_visible_to(u, username): return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept): return err("forbidden department scope", 403)
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
        if not is_user_visible_to(u, username): return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept): return err("forbidden department scope", 403)
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
        if not is_user_visible_to(u, username): return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept): return err("forbidden department scope", 403)
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
        if not is_user_visible_to(u, username): return err("forbidden username scope", 403)
        q["username"] = username
    if dept:
        if not is_dept_visible_to(u, dept): return err("forbidden department scope", 403)
        q["department"] = dept
    if device:
        q["user_mac_id"] = device

    try:
        return ok(insights.hourly(q))
    except Exception as e:
        return err(str(e), 400)

def bootstrap_admin_if_missing():
    if users.count_documents({}) == 0:
        users.insert_one({
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "role": ROLE_C_SUITE,
            "department": "IT",
            "is_active": True
        })
        print("[BOOT] Default admin created: admin/admin123 (CHANGE ASAP).")

if __name__ == "__main__":
    ensure_indexes()
    bootstrap_admin_if_missing()
    app.run(host=HOST, port=PORT, debug=DEBUG)
