import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "Discovery_Agent")

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "720"))

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
DEBUG = os.getenv("DEBUG", "1") == "1"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))
