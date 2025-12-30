import time, json, base64, hashlib, hmac, os
from typing import Any, Dict, Optional
from config import JWT_SECRET, JWT_EXP_MINUTES
from db import users

PBKDF2_ITERS = 200_000

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS, dklen=32)
    return base64.urlsafe_b64encode(salt + dk).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(stored.encode())
        salt, dk = raw[:16], raw[16:]
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS, dklen=32)
        return hmac.compare_digest(test, dk)
    except Exception:
        return False

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode())

def jwt_sign(payload: Dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"

def jwt_verify(token: str) -> Dict[str, Any]:
    h, p, s = token.split(".")
    msg = f"{h}.{p}".encode()
    expected = hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_decode(s), expected):
        raise ValueError("Bad signature")
    payload = json.loads(_b64url_decode(p).decode())
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("Expired")
    return payload

def issue_token(username: str) -> str:
    exp = int(time.time() + JWT_EXP_MINUTES * 60)
    return jwt_sign({"sub": username, "exp": exp})

def get_user_public(username: str) -> Optional[Dict[str, Any]]:
    return users.find_one({"username": username}, {"_id": 0, "password_hash": 0})
