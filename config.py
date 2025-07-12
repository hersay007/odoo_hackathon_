import os

# Replace with your Neon PostgreSQL connection URL
DATABASE_URL = os.environ.get("DATABASE_URL") or "postgresql://username:password@host:port/dbname"
SECRET_KEY = os.environ.get("SECRET_KEY") or "supersecretkey"
