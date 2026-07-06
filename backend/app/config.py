"""Central configuration.

Security decision: every secret and tunable is loaded from the environment
via pydantic-settings — nothing is hardcoded. Pydantic validates types at
startup so a misconfigured deployment fails fast instead of running insecurely.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    environment: str = "development"
    app_name: str = "SentinelX Auth API"
    api_v1_prefix: str = "/api/v1"

    # Secrets (no defaults for the truly sensitive ones — must be provided)
    jwt_secret: str
    fernet_key: str

    # Database
    database_url: str

    # Token lifetimes
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 604800
    password_reset_ttl_seconds: int = 1800

    # Lockout
    max_failed_logins: int = 5
    lockout_seconds: int = 900

    # Cookies
    cookie_secure: bool = False
    cookie_domain: str | None = None
    cookie_samesite: str = "strict"  # strict | lax | none (none requires Secure)

    # CORS
    cors_origins: str = "http://localhost:8741"

    # Rate limiting
    rate_limit_storage_uri: str = "memory://"
    rate_limit_enabled: bool = True  # disable only for tests / load-testing

    # Email
    email_transport: str = "console"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    email_from: str = "no-reply@sentinelx.local"
    frontend_reset_url: str = "http://localhost:8741/reset-password"

    jwt_algorithm: str = "HS256"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
