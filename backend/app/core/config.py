"""Centralized application configuration.

All configuration originates from environment variables.
The application fails at startup if required variables are missing.
"""

import re
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.security import is_valid_allowlist_entry, normalize_allowlist_entry

_MIN_JWT_SECRET_LENGTH = 64
_MIN_PROXY_SECRET_LENGTH = 32
SUPPORTED_AI_PROVIDERS = frozenset({"openrouter"})
_MODEL_ID_PATTERN = re.compile(r"[\w.-]+/[\w.-]+(:[\w-]+)?")
# OpenRouter's router that only ever picks among free models.
FREE_ROUTER_MODEL = "openrouter/free"


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
    # New accounts allowed per client IP in a sliding hour.
    registrations_per_ip_per_hour: int = Field(default=10, ge=1)
    # Shared secret a trusted reverse proxy sends with every request. When
    # set, the proxy's X-AVAP-Client-IP header is believed for requests that
    # carry it (see app.core.security.resolve_client_ip). Empty = off: only
    # the direct connection address is ever used.
    trusted_proxy_secret: SecretStr = SecretStr("")

    # Database
    database_url: str | None = None
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "avap"
    postgres_user: str = "avap_user"
    postgres_password: str = "changeme"  # noqa: S105 -- dev placeholder, matches .env.example

    # Scanner
    nmap_executable: str = "/usr/bin/nmap"
    # Outer process deadline for QUICK scans (seconds).
    # Formula: nmap --host-timeout 10m (600s) + 5m buffer (300s) = 900s.
    scan_timeout: int = Field(default=900, ge=1)
    # Outer process deadline for FULL scans (seconds).
    # Formula: nmap --host-timeout 90m (5400s) + 15m buffer (900s) = 6300s.
    full_scan_timeout: int = Field(default=6300, ge=1)
    # Scan mode for the FULL profile: auto | privileged | unprivileged
    nmap_scan_mode: str = "auto"

    # AI Providers
    # AI. Each user supplies their own provider key in the Profile page;
    # there is deliberately no server-wide key setting.
    ai_provider: str = "openrouter"
    ai_request_timeout_seconds: int = Field(default=60, ge=1)
    ai_max_tokens: int = Field(default=1024, ge=1)
    # Free models only: an id ending in ":free", or "openrouter/free" (a
    # router that picks among free models). Anything else is refused.
    openrouter_model: str = "google/gemma-4-31b-it:free"
    # OpenRouter provider.data_collection: "allow" or "deny". "deny" keeps
    # requests off providers that store or train on prompts, but can leave
    # no free provider available for a model.
    openrouter_data_collection: str = "allow"
    # AI-inferred findings are advisory: they are shown and reported but
    # contribute nothing to the deterministic risk score unless enabled.
    ai_findings_in_risk: bool = False

    # Reporting
    report_output_directory: str = "./generated_reports"
    scanner_output_directory: str = "./scan_output"

    # Raw scan output storage: "local" (a directory) or "s3" (AWS S3 or any
    # S3-compatible endpoint). S3 credentials are read by boto3 from its
    # standard chain (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or an IAM role),
    # never from these settings.
    storage_backend: str = "local"
    # Its own folder, separate from scan_output/ and generated_reports/.
    storage_local_directory: str = "./storage"
    s3_bucket: str = ""
    s3_region: str = ""
    # Only for S3-compatible services; empty means AWS.
    s3_endpoint_url: str = ""
    # "AES256" (SSE-S3) or "aws:kms"; empty disables (some S3-compatible
    # servers reject the header).
    s3_server_side_encryption: str = "AES256"

    # Logging
    log_level: str = "INFO"
    log_directory: str = "./logs"

    # Concurrency. Enforced from database state by ScanService.create_scan.
    max_concurrent_scans: int = Field(default=2, ge=1)

    # Target scope. CIDR targets broader than this prefix length are
    # rejected so a typo (e.g. 0.0.0.0/0) cannot launch a sweep of a huge
    # or public address range. /16 = 65,536 addresses.
    min_cidr_prefix_length: int = Field(default=16, ge=0, le=32)
    # Comma-separated IPv4 addresses, IPv4 CIDRs and hostnames a public
    # deployment may scan. Empty = no restriction beyond the rules above.
    scan_target_allowlist: str = ""

    @field_validator("scan_target_allowlist")
    @classmethod
    def validate_scan_target_allowlist(cls, value: str) -> str:
        """Refuse startup on an entry that is not an IP, CIDR or hostname."""
        for entry in value.split(","):
            normalized = normalize_allowlist_entry(entry)
            if normalized and not is_valid_allowlist_entry(normalized):
                raise ValueError(
                    "SCAN_TARGET_ALLOWLIST entries must be IPv4 addresses, "
                    "IPv4 CIDR ranges or hostnames."
                )
        return value

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

    @field_validator("storage_backend")
    @classmethod
    def validate_storage_backend(cls, value: str) -> str:
        backend = value.strip().lower()
        if backend not in {"local", "s3"}:
            raise ValueError("STORAGE_BACKEND must be 'local' or 's3'.")
        return backend

    @field_validator("s3_endpoint_url")
    @classmethod
    def validate_s3_endpoint_url(cls, value: str) -> str:
        url = value.strip()
        if url and not url.startswith(("https://", "http://")):
            raise ValueError("S3_ENDPOINT_URL must be an http(s) URL.")
        return url

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

    @field_validator("openrouter_model")
    @classmethod
    def validate_openrouter_model(cls, value: str) -> str:
        """Only free models: "<org>/<model>:free" or the free router."""
        model = value.strip()
        is_free_variant = _MODEL_ID_PATTERN.fullmatch(model) and model.endswith(
            ":free"
        )
        if model != FREE_ROUTER_MODEL and not is_free_variant:
            raise ValueError(
                "OPENROUTER_MODEL must be a free model: an id ending in ':free' "
                f"or '{FREE_ROUTER_MODEL}'."
            )
        return model

    @field_validator("openrouter_data_collection")
    @classmethod
    def validate_openrouter_data_collection(cls, value: str) -> str:
        policy = value.strip().lower()
        if policy not in {"allow", "deny"}:
            raise ValueError("OPENROUTER_DATA_COLLECTION must be 'allow' or 'deny'.")
        return policy

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
        proxy_secret = self.trusted_proxy_secret.get_secret_value()
        if proxy_secret and len(proxy_secret) < _MIN_PROXY_SECRET_LENGTH:
            raise ValueError(
                "TRUSTED_PROXY_SECRET must be empty or at least "
                f"{_MIN_PROXY_SECRET_LENGTH} random characters."
            )

    def validate_ai_settings(self) -> None:
        """Fail fast on a provider this build does not implement (for
        example a stale AI_PROVIDER=openrouter from an older .env)."""
        if self.ai_provider not in SUPPORTED_AI_PROVIDERS:
            raise ValueError(
                f"AI_PROVIDER must be one of {sorted(SUPPORTED_AI_PROVIDERS)}."
            )

    def validate_storage_settings(self) -> None:
        """Fail fast on an incomplete S3 configuration."""
        if self.storage_backend == "s3" and not self.s3_bucket.strip():
            raise ValueError("S3_BUCKET is required when STORAGE_BACKEND=s3.")

    @property
    def storage_local_path(self) -> Path:
        """Root directory of the local object store."""
        return Path(self.storage_local_directory)

    @property
    def scan_target_allowlist_entries(self) -> list[str]:
        """The normalized allowlist; empty means unrestricted."""
        entries = (
            normalize_allowlist_entry(entry)
            for entry in self.scan_target_allowlist.split(",")
        )
        return [entry for entry in entries if entry]

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
