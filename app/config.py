from functools import lru_cache
import os


class Settings:
    # MongoDB
    mongo_url: str = os.getenv("MONGO_URL", "mongodb://localhost:27017")
    mongo_db_name: str = os.getenv("MONGO_DB_NAME", "auth_service")

    # RS256 signing key
    keys_dir: str = os.getenv("KEYS_DIR", "./keys")

    # Tokens
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    refresh_token_expire_days: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

    # CORS — comma-separated list of allowed browser origins
    cors_allowed_origins: list[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
