from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARDIAN_", extra="ignore")

    app_name: str = "ECS Guardian Trust"
    database_url: str = "sqlite:///./data/guardian_trust.db"
    host: str = "0.0.0.0"
    port: int = 8080
    max_delegation_depth: int = 3
    seed_on_start: bool = True


def data_dir() -> Path:
    path = Path("data")
    path.mkdir(parents=True, exist_ok=True)
    return path


settings = Settings()
