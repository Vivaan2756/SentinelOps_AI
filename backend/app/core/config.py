"""Application configuration using Pydantic Settings."""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for SentinelOps AI backend."""

    # Project Information
    PROJECT_NAME: str = "SentinelOps AI"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = Field(default="development", description="development, test, or production")
    DEBUG: bool = Field(default=False, description="Debug mode flag")

    # Database Configuration (PostgreSQL 18)
    # Default connection string points to local development database; can be overridden by DATABASE_URL env var
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/sentinelops_dev",
        description="SQLAlchemy database connection URI",
    )

    # Security & Authentication (JWT + Bcrypt)
    SECRET_KEY: str = Field(
        default="sentinelops-insecure-dev-secret-key-change-in-production-1234567890",
        description="Secret key for signing JWT tokens",
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 hours

    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Standard logging level")

    # Detector Engine Configuration
    DETECTOR_TIMEOUT_SECONDS: float = Field(
        default=3.0, description="Probe timeout in seconds for health and metrics checks"
    )
    ALLOW_LOCAL_PROBES: bool = Field(
        default=True,
        description="Allow loopback/localhost targets during local development/demo testing",
    )
    DETECTOR_POLL_INTERVAL_SECONDS: float = Field(
        default=10.0, description="Interval in seconds between background detector polling cycles"
    )
    DETECTOR_MAX_CONCURRENCY: int = Field(
        default=5, description="Maximum concurrent service evaluations during background polling"
    )
    DETECTOR_POLLER_ENABLED: bool = Field(
        default=True, description="Enable autonomous background detector polling"
    )

    # Agentic AI Incident Investigation (Gemini 2.5 Flash + LangGraph)
    GEMINI_API_KEY: str | None = Field(
        default=None, description="Google Gemini API key for Agentic SRE investigation"
    )
    GEMINI_MODEL: str = Field(
        default="gemini-2.5-flash", description="Gemini model identifier for investigation"
    )
    INVESTIGATION_TIMEOUT_SECONDS: float = Field(
        default=30.0, description="Overall timeout for investigation graph execution"
    )
    INVESTIGATION_PROMPT_VERSION: str = Field(
        default="v1.0", description="Prompt template version identifier"
    )
    MAX_EVIDENCE_ITEMS: int = Field(
        default=20, description="Maximum number of diagnostic evidence items collected per run"
    )
    MAX_EVIDENCE_PAYLOAD_BYTES: int = Field(
        default=16384, description="Maximum byte length retained for diagnostic payloads (16KB)"
    )

    # Remediation & Approvals Configuration (Phase 4.2)
    APPROVAL_EXPIRY_HOURS: int = Field(
        default=24, description="Default expiration window in hours for pending remediation approvals"
    )
    ALLOW_SELF_APPROVAL: bool = Field(
        default=False,
        description="Allow requester to approve their own request; strictly forbidden for high-risk in production",
    )

    # Autonomous Remediation Execution Worker Configuration (Phase 1 / P0.3)
    WORKER_ENABLED: bool = Field(
        default=True, description="Enable autonomous background remediation worker polling"
    )
    WORKER_POLL_INTERVAL_SECONDS: float = Field(
        default=2.0, description="Interval in seconds between background worker polling cycles"
    )
    WORKER_SHUTDOWN_GRACE_PERIOD_SECONDS: float = Field(
        default=10.0, description="Grace period in seconds for worker in-flight task completion during shutdown"
    )

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
