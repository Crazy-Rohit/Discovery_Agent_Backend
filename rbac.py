from typing import Dict, Any
from db import users

ROLE_C_SUITE = "C_SUITE"
ROLE_DEPT_HEAD = "DEPARTMENT_HEAD"
ROLE_TEAM_MEMBER = "DEPARTMENT_MEMBER"


def _role(user: Dict[str, Any]) -> str:
    return str(user.get("role_key") or user.get("role") or "").upper()


def _email(user: Dict[str, Any]) -> str:
    return str(user.get("company_username_norm") or user.get("company_username") or user.get("username") or "").lower()


def scope_filter_for_logs(user: Dict[str, Any]) -> Dict[str, Any]:
    role = _role(user)

    if role == ROLE_C_SUITE:
        return {}

    if role == ROLE_DEPT_HEAD:
        return {"department": user.get("department")}

    # department member: only own email
    return {"company_username": _email(user)}


def is_user_visible_to(user: Dict[str, Any], target_email: str) -> bool:
    role = _role(user)
    target_email = (target_email or "").strip().lower()

    if role == ROLE_C_SUITE:
        return True

    if role == ROLE_DEPT_HEAD:
        t = users.find_one({"company_username_norm": target_email}, {"department": 1})
        if not t:
            t = users.find_one({"company_username": target_email}, {"department": 1})
        return bool(t and t.get("department") == user.get("department"))

    return _email(user) == target_email


def is_dept_visible_to(user: Dict[str, Any], dept: str) -> bool:
    role = _role(user)
    dept = (dept or "").strip()

    if role == ROLE_C_SUITE:
        return True

    user_dept = (user.get("department") or "").strip()
    return user_dept == dept
