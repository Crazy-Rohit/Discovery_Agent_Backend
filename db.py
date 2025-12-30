from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from config import MONGO_URI, DB_NAME

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

users: Collection = db["users"]
logs: Collection = db["logs"]
departments: Collection = db["departments"]

def ensure_indexes():
    users.create_index([("username", ASCENDING)], unique=True)

    logs.create_index([("user_mac_id", ASCENDING)], unique=True)
    logs.create_index([("username", ASCENDING)])
    logs.create_index([("department", ASCENDING)])
    logs.create_index([("updated_at", ASCENDING)])

    departments.create_index([("name", ASCENDING)], unique=True)
