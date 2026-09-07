from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARDIAN_QA_", extra="ignore")

    app_name: str = "ECS Guardian Quality"
    database_url: str = "sqlite:///./data/guardian_quality.db"
    host: str = "0.0.0.0"
    port: int = 8080
    seed_on_start: bool = True
    pass_threshold: float = 0.8


def data_dir() -> Path:
    path = Path("data")
    path.mkdir(parents=True, exist_ok=True)
    return path


settings = Settings()
