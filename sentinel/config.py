from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    llm_provider: Literal["gemini", "openai", "ollama"] = "gemini"
    scout_model: str = "gemini-3.5-flash-lite"
    gemini_model: str = "gemini-3.5-flash-lite"
    red_team_model: str = "gpt-4o"
    blue_team_model: str = "deepseek-coder:7b"
    ollama_host: str = "http://127.0.0.1:11434"
    max_retries: int = 5
    command_timeout_seconds: int = 120
    solc_binary: Path | None = None
    mythril_binary: Path | None = None
    static_binary: Path | None = None
    mythril_execution_timeout_seconds: int = Field(default=60, ge=1, le=3600)
    mythril_transaction_count: int = Field(default=2, ge=1, le=10)
    mythril_max_sources: int = Field(default=10, ge=1, le=500)
    use_docker: bool = True
    output_dir: Path = Path("reports")


settings = Settings()
