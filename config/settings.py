"""
config/settings.py
Central configuration loaded from .env.
All modules import from here — never read env vars directly.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # LLM
    llm_provider: str = "openai"
    llm_api_key: str = "sk-placeholder"
    llm_model: str = "gpt-4o"
    llm_base_url: str = "https://api.openai.com/v1"

    # Database
    database_url: str = "sqlite+aiosqlite:///./cyber.db"

    # Ports
    email_server_port: int = 8001
    pdf_server_port: int = 8002
    endpoint_server_port: int = 8003
    filesystem_server_port: int = 8004
    network_server_port: int = 8005
    threatintel_server_port: int = 8006
    response_server_port: int = 8007
    memory_server_port: int = 8008
    orchestrator_port: int = 8000

    # Risk thresholds
    risk_low: int = 30
    risk_medium: int = 70
    risk_high: int = 120
    risk_critical: int = 160

    # Response mode
    response_mode: str = "simulate"

    # Threat intel
    vt_api_key: str = ""


settings = Settings()
