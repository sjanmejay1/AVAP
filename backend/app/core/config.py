"""Centralized application configuration.

All configuration originates from environment variables.
The application fails at startup if required variables are missing.
"""

from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_MIN_JWT_SECRET_LENGTH = 64


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "AVAP"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # CORS. Comma-separated, explicit list of browser origins allowed to
    # call the API with credentials (the refresh-token cookie). Never a
    # wildcard. The same list is the Origin allowlist for /auth/refresh and
    # /auth/logout.
    cors_allowed_origins: str = "http://localhost:3000"

    # Authentication. JWT_SECRET_KEY and APP_ENCRYPTION_KEY have no default
    # and are checked by validate_security_settings() at startup.
    jwt_secret_key: SecretStr = SecretStr("")
    app_encryption_key: SecretStr = SecretStr("")
    access_token_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_days: int = Field(default=7, ge=1, le=30)
    # Secure cookies are sent only over HTTPS; browsers treat
    # http://localhost as secure, so the default works in local dev too.
    refresh_cookie_secure: bool = True
    login_max_failures: int = Field(default=5, ge=1)
    login_failure_window_minutes: int = Field(default=15, ge=1)

    # Database
    database_url: str | None = None
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "avap"
    postgres_user: str = "avap_user"
    postgres_password: str = "changeme"  # noqa: S105 -- dev placeholder, matches .env.example

    # Scanner
    nmap_executable: str = "/usr/bin/nmap"
    # Default outer process deadline for quick/discovery scans (seconds)
    scan_timeout: int = Field(default=300, ge=1)
    # Outer process deadline for FULL scans (seconds).
    # Formula: nmap --host-timeout 90m (5400s) + 15m buffer (900s) = 6300s.
    full_scan_timeout: int = Field(default=6300, ge=1)
    # Scan mode for the FULL profile: auto | privileged | unprivileged
    nmap_scan_mode: str = "auto"

    # AI Providers
    ai_provider: str = "openrouter"
    ai_request_timeout_seconds: int = Field(default=30, ge=1)
    ai_max_tokens: int = Field(default=1024, ge=1)
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "meta-llama/llama-3.1-8b-instruct:free"
    groq_api_key: str = ""
    gemini_api_key: str = ""
    huggingface_api_key: str = ""

    # Reporting
    report_output_directory: str = "./generated_reports"
    scanner_output_directory: str = "./scan_output"

    # Logging
    log_level: str = "INFO"
    log_directory: str = "./logs"

    # Concurrency. Enforced from database state by ScanService.create_scan.
    max_concurrent_scans: int = Field(default=2, ge=1)

    # Target scope. CIDR targets broader than this prefix length are
    # rejected so a typo (e.g. 0.0.0.0/0) cannot launch a sweep of a huge
    # or public address range. /16 = 65,536 addresses.
    min_cidr_prefix_length: int = Field(default=16, ge=0, le=32)

    @field_validator("nmap_scan_mode")
    @classmethod
    def validate_nmap_scan_mode(cls, value: str) -> str:
        """Validate NMAP_SCAN_MODE is one of the accepted values."""
        allowed = {"auto", "privileged", "unprivileged"}
        lower = value.strip().lower()
        if lower not in allowed:
            allowed_str = ", ".join(sorted(allowed))
            raise ValueError(
                f"Invalid nmap_scan_mode: '{value}'. Allowed: {allowed_str}"
            )
        return lower

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Validate that log level is a recognized Python logging level."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_value = value.upper()
        if upper_value not in allowed:
            raise ValueError(
                f"Invalid log level: {value}. Allowed: {', '.join(sorted(allowed))}"
            )
        return upper_value

    @field_validator("ai_provider")
    @classmethod
    def normalize_ai_provider(cls, value: str) -> str:
        """Normalize the configured AI provider name for case-insensitive matching."""
        return value.strip().lower()

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        """Validate environment name."""
        allowed = {"development", "staging", "production", "testing"}
        lower_value = value.lower()
        if lower_value not in allowed:
            raise ValueError(
                f"Invalid environment: {value}. Allowed: {', '.join(sorted(allowed))}"
            )
        return lower_value

    def validate_security_settings(self) -> None:
        """Fail fast when the auth secrets are missing or weak.

        Raises:
            ValueError: naming the variable at fault, never its value.
        """
        if len(self.jwt_secret_key.get_secret_value()) < _MIN_JWT_SECRET_LENGTH:
            raise ValueError(
                "JWT_SECRET_KEY must be set to at least "
                f"{_MIN_JWT_SECRET_LENGTH} random characters."
            )
        try:
            Fernet(self.app_encryption_key.get_secret_value().encode())
        except ValueError:
            raise ValueError(
                "APP_ENCRYPTION_KEY must be a Fernet key "
                "(32 url-safe base64-encoded bytes)."
            ) from None

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        """Parse the comma-separated CORS allowlist into individual origins.

        Blank entries (trailing commas, empty configuration) are dropped so
        an empty string is never passed to CORSMiddleware as an origin.
        """
        return [
            origin.strip()
            for origin in self.cors_allowed_origins.split(",")
            if origin.strip()
        ]

    @property
    def effective_database_url(self) -> str:
        """Return the database URL, constructing from parts if not provided."""
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def log_directory_path(self) -> Path:
        """Return the log directory as a Path object."""
        return Path(self.log_directory)

    @property
    def report_output_path(self) -> Path:
        """Return the report output directory as a Path object."""
        return Path(self.report_output_directory)

    @property
    def scanner_output_path(self) -> Path:
        """Return the scanner output directory as a Path object."""
        return Path(self.scanner_output_directory)


@lru_cache
def get_settings() -> Settings:
    """Create and return application settings.

    Settings are loaded from environment variables and .env file.
    The result is cached so the same Settings instance is reused across the
    application.  Tests that need a fresh instance call
    ``get_settings.cache_clear()`` before exercising the function.
    """
    return Settings()
