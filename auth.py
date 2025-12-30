from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

from config import JWT_SECRET
from db import users

def hash_password(pw: str) -> str:
    return generate_password_hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return check_password_hash(pw_hash or "", pw or "")

def issue_token(user_mac_id: str, role_key: str = "DEPARTMENT_MEMBER"):
    payload = {
        "sub": str(user_mac_id),   # identity = MAC (_id)
        "role_key": role_key,
        "exp": datetime.utcnow() + timedelta(days=7),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def jwt_verify(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

def get_user_public(user_mac_id: str):
    user = users.find_one({"_id": str(user_mac_id)})
    if not user:
        return None

    email = user.get("company_username")
    return {
        "_id": str(user.get("_id")),
        "user_mac_id": user.get("user_mac_id") or str(user.get("_id")),
        "company_username": email,

        # aliases to keep older code from breaking
        "username": email,
        "role": user.get("role_key", "DEPARTMENT_MEMBER"),

        "pc_username": user.get("pc_username"),
        "department": user.get("department"),
        "role_key": user.get("role_key", "DEPARTMENT_MEMBER"),

        "license_accepted": bool(user.get("license_accepted", False)),
        "license_version": user.get("license_version", "1.0"),
        "license_accepted_at": user.get("license_accepted_at"),

        "created_at": user.get("created_at"),
        "last_seen_at": user.get("last_seen_at"),

        "is_active": bool(user.get("is_active", True)),
    }
