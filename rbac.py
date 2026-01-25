from functools import wraps
from flask import jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt

# -----------------------------
# Roles (single source of truth)
# -----------------------------
ROLE_C_SUITE = "C_SUITE"
ROLE_DEPT_HEAD = "DEPARTMENT_HEAD"
ROLE_DEPT_MEMBER = "DEPARTMENT_MEMBER"

# Backward-compatible alias (your app.py expects ROLE_TEAM_MEMBER)
ROLE_TEAM_MEMBER = ROLE_DEPT_MEMBER

DASHBOARD_ALLOWED_ROLES = {ROLE_C_SUITE, ROLE_DEPT_HEAD}


def init_rbac(app):
    """
    Placeholder to keep compatibility if older code calls init_rbac(app).
    We store identity into flask.g inside decorators after JWT verification.
    """
    return


def require_dashboard_access():
    """
    Protect dashboard endpoints:
      - C_SUITE: allowed
      - DEPARTMENT_HEAD: allowed (department-scoped)
      - DEPARTMENT_MEMBER: denied
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt() or {}

            role_key = (claims.get("role_key") or claims.get("role") or "").strip().upper()
            if role_key not in DASHBOARD_ALLOWED_ROLES:
                return jsonify({"ok": False, "error": "forbidden", "message": "Dashboard access denied"}), 403

            g.identity = {
                "user_id": claims.get("sub"),
                "mac_id": claims.get("mac_id"),
                "company_username": claims.get("company_username"),
                "role_key": role_key,
                "department": claims.get("department"),
            }
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_csuite():
    """
    Only C_SUITE can access certain endpoints.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt() or {}

            role_key = (claims.get("role_key") or claims.get("role") or "").strip().upper()
            if role_key != ROLE_C_SUITE:
                return jsonify({"ok": False, "error": "forbidden", "message": "C_SUITE only"}), 403

            g.identity = {
                "user_id": claims.get("sub"),
                "mac_id": claims.get("mac_id"),
                "company_username": claims.get("company_username"),
                "role_key": role_key,
                "department": claims.get("department"),
            }
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def scope_filter_for_logs(identity: dict, department_override: str = None) -> dict:
    """
    Returns a MongoDB filter that scopes data access based on role.

    - C_SUITE: no restriction (optionally allow department filter)
    - DEPARTMENT_HEAD: restrict to their own department only
    """
    role_key = (identity or {}).get("role_key", "").strip().upper()
    dept = (identity or {}).get("department")

    if role_key == ROLE_C_SUITE:
        if department_override:
            return {"department": department_override}
        return {}

    if role_key == ROLE_DEPT_HEAD:
        if not dept:
            return {"_id": {"$in": []}}  # no access
        return {"department": dept}

    # DEPARTMENT_MEMBER (or unknown): no access for dashboard
    return {"_id": {"$in": []}}
