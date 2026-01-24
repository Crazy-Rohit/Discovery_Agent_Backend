from flask import request
from pymongo.errors import DuplicateKeyError
from db import departments

def list_departments():
    return [d["name"] for d in departments.find({}, {"_id": 0, "name": 1}).sort("name", 1)]

def create_department():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("name required")
    try:
        departments.insert_one({"name": name})
    except DuplicateKeyError:
        raise ValueError("department already exists")
    return name
