from pymongo import MongoClient, ASCENDING
from pymongo.errors import OperationFailure
from config import MONGO_URI, MONGO_DB

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

# Collections
users = db["users"]
departments = db["departments"]
logs = db["logs"]
screenshots = db["screenshots"]

def _find_index_by_keys(col, keys):
    """
    keys: list of tuples e.g. [("company_username", 1)]
    returns index name if an index exists with exactly these keys; else None
    """
    info = col.index_information()
    for name, meta in info.items():
        # meta["key"] is list of tuples
        if meta.get("key") == keys:
            return name, meta
    return None, None

def _ensure_index(col, keys, unique=False):
    """
    Ensures an index exists with the given keys and unique option.
    - If exists with same keys + same unique => do nothing
    - If exists with same keys but different unique => drop and recreate
    - Otherwise create
    """
    existing_name, meta = _find_index_by_keys(col, keys)
    if existing_name:
        existing_unique = bool(meta.get("unique", False))
        if existing_unique == bool(unique):
            return  # already correct
        # conflict: same keys but unique differs -> must drop & recreate
        try:
            col.drop_index(existing_name)
        except Exception:
            pass

    # Create without specifying a name (Mongo will reuse standard naming)
    col.create_index(keys, unique=unique)

def ensure_indexes():
    # ---------- Users ----------
    _ensure_index(users, [("company_username", ASCENDING)], unique=True)
    _ensure_index(users, [("department", ASCENDING)], unique=False)
    _ensure_index(users, [("role_key", ASCENDING)], unique=False)
    _ensure_index(users, [("last_seen_at", ASCENDING)], unique=False)

    # ---------- Departments ----------
    _ensure_index(departments, [("name", ASCENDING)], unique=True)

    # ---------- Logs ----------
    # logs must NOT be unique per user_mac_id
    _ensure_index(logs, [("user_mac_id", ASCENDING)], unique=False)
    _ensure_index(logs, [("department", ASCENDING)], unique=False)
    _ensure_index(logs, [("timestamp", ASCENDING)], unique=False)

    # ---------- Screenshots ----------
    _ensure_index(screenshots, [("user_mac_id", ASCENDING)], unique=False)
    _ensure_index(screenshots, [("department", ASCENDING)], unique=False)
    _ensure_index(screenshots, [("timestamp", ASCENDING)], unique=False)
