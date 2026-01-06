from typing import Dict, Any
from db import users

ROLE_C_SUITE = "C_SUITE"
ROLE_DEPT_HEAD = "DEPARTMENT_HEAD"
ROLE_TEAM_MEMBER = "DEPARTMENT_MEMBER"


def _role(user: Dict[str, Any]) -> str:
    return str(user.get("role_key") or user.get("role") or "").upper().strip()


def _email(user: Dict[str, Any]) -> str:
    return str(
        user.get("company_username_norm")
        or user.get("company_username")
        or user.get("username")
        or ""
    ).lower().strip()


def scope_filter_for_logs(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    IMPORTANT: Your logs collection stores the email in `company_username`
    and department in `department`.
    """
    role = _role(user)

    if role == ROLE_C_SUITE:
        return {}

    if role == ROLE_DEPT_HEAD:
        return {"department": user.get("department")}

    # Member: only their own data
    return {"company_username": _email(user)}


def scope_filter_for_users(user: Dict[str, Any]) -> Dict[str, Any]:
    """RBAC scope for users collection."""
    role = _role(user)

    if role == ROLE_C_SUITE:
        return {}

    if role == ROLE_DEPT_HEAD:
        return {"department": user.get("department")}

    return {"company_username_norm": _email(user)}


def is_user_visible_to(user: Dict[str, Any], target_email: str) -> bool:
    """Visibility rule for requesting someone else's data."""
    role = _role(user)
    target_email = (target_email or "").strip().lower()

    if role == ROLE_C_SUITE:
        return True

    if role == ROLE_DEPT_HEAD:
        t = users.find_one({"company_username_norm": target_email}, {"department": 1})
        if not t:
            t = users.find_one({"company_username": target_email}, {"department": 1})
        return bool(t and (t.get("department") or "").strip() == (user.get("department") or "").strip())

    return _email(user) == target_email


def is_dept_visible_to(user: Dict[str, Any], dept: str) -> bool:
    role = _role(user)
    dept = (dept or "").strip()

    if role == ROLE_C_SUITE:
        return True

    return (user.get("department") or "").strip() == dept
