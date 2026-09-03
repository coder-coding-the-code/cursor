from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SEMANTIC_FW_", extra="ignore")

    app_name: str = "ECS Guardian Semantic"
    database_url: str = "sqlite:///./data/semantic_firewall.db"
    host: str = "0.0.0.0"
    port: int = 8080
    seed_on_start: bool = True
    max_session_turns: int = 12
    max_structure_depth: int = 10
    max_payload_chars: int = 50_000
    sunglasses_enabled: bool = True


def data_dir() -> Path:
    path = Path("data")
    path.mkdir(parents=True, exist_ok=True)
    return path


settings = Settings()
