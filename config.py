import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "Plaformers")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///lost_and_found.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
