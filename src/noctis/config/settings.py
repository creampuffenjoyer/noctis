"""Config engine: reads model credentials and scan defaults from .env / environment."""
from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ModelProvider(StrEnum):
    GEMINI = "gemini"
    OPENAI = "openai"
    CLAUDE = "claude"
    OPENROUTER = "openrouter"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    gemini_api_key: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    openrouter_api_key: str | None = None

    default_model: ModelProvider = ModelProvider.GEMINI

    max_workers: int = 3
    requests_per_second: float = 10.0
    max_scan_depth: int = 5
    confirm_destructive: bool = True

    report_output_dir: Path = Path("./reports")
    workspace_dir: Path = Path("./workspaces")

    interactsh_server: str = "oast.pro"

    def api_key_for(self, provider: ModelProvider) -> str | None:
        return {
            ModelProvider.GEMINI: self.gemini_api_key,
            ModelProvider.OPENAI: self.openai_api_key,
            ModelProvider.CLAUDE: self.anthropic_api_key,
            ModelProvider.OPENROUTER: self.openrouter_api_key,
        }[provider]


_settings: Settings | None = None


def get_settings(*, reload: bool = False) -> Settings:
    """Return the process-wide Settings singleton, loading it on first use."""
    global _settings
    if _settings is None or reload:
        _settings = Settings()
    return _settings
