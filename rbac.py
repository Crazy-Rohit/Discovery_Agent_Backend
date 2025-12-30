from typing import Dict, Any
from db import users

ROLE_C_SUITE = "c_suite"
ROLE_DEPT_HEAD = "department_head"
ROLE_TEAM_MEMBER = "team_member"

VALID_ROLES = {ROLE_C_SUITE, ROLE_DEPT_HEAD, ROLE_TEAM_MEMBER}

def scope_filter_for_logs(user: Dict[str, Any]) -> Dict[str, Any]:
    role = user.get("role")
    if role == ROLE_C_SUITE:
        return {}
    if role == ROLE_DEPT_HEAD:
        return {"department": user.get("department")}
    return {"username": user.get("username")}

def is_user_visible_to(user: Dict[str, Any], target_username: str) -> bool:
    role = user.get("role")
    if role == ROLE_C_SUITE:
        return True
    if role == ROLE_DEPT_HEAD:
        t = users.find_one({"username": target_username}, {"department": 1})
        return bool(t and t.get("department") == user.get("department"))
    return user.get("username") == target_username

def is_dept_visible_to(user: Dict[str, Any], dept: str) -> bool:
    role = user.get("role")
    if role == ROLE_C_SUITE:
        return True
    if role == ROLE_DEPT_HEAD:
        return user.get("department") == dept
    return user.get("department") == dept
