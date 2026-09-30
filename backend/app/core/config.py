from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # API Gateway
    PROJECT_NAME: str = "Cloud Security Monitoring & Threat Detection Platform"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "dev-insecure-secret-key-change-in-production-min-32-chars-long"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://secplatform_user:secplatform_dev_password@localhost:5432/secplatform_db"
    POSTGRES_USER: str = "secplatform_user"
    POSTGRES_PASSWORD: str = "secplatform_dev_password"
    POSTGRES_DB: str = "secplatform_db"

    # Redis Cache & Streaming Buffer
    REDIS_URL: str = "redis://localhost:6379/0"

    # Seed Config
    DEV_SEED_PASSWORD: str = "DevSecOps2026!ChangeMe"

    # Synthetic Engine Settings
    SYNTHETIC_EMISSION_RATE_SECONDS: int = 2
    DRY_RUN_MODE: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
