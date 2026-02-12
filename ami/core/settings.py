"""Application settings loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict

ACCESS_TOKEN_TTL_DEFAULT = 3600
REFRESH_TOKEN_TTL_DEFAULT = 2_592_000
AUTH_CODE_TTL_DEFAULT = 60
DB_POOL_SIZE_DEFAULT = 5
DB_MAX_OVERFLOW_DEFAULT = 10
DB_PORT_DEFAULT = 5432


class DatabaseSettings(BaseSettings):
    """PostgreSQL connection settings."""

    model_config = SettingsConfigDict(env_prefix="AUTH_DB_")

    host: str = "localhost"
    port: int = DB_PORT_DEFAULT
    user: str = "ami"
    password: str = "ami"
    database: str = "ami"
    pool_size: int = DB_POOL_SIZE_DEFAULT
    max_overflow: int = DB_MAX_OVERFLOW_DEFAULT

    @property
    def async_url(self) -> str:
        """Build async PostgreSQL connection URL."""
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
        )


class AuthSettings(BaseSettings):
    """OIDC and auth-specific settings."""

    model_config = SettingsConfigDict(env_prefix="AUTH_")

    issuer_url: str = "http://localhost:8000"
    cors_origins: str = ""
    dataops_internal_token: str = ""
    signing_key_encryption_key: str = ""
    access_token_ttl: int = ACCESS_TOKEN_TTL_DEFAULT
    refresh_token_ttl: int = REFRESH_TOKEN_TTL_DEFAULT
    auth_code_ttl: int = AUTH_CODE_TTL_DEFAULT

    def get_cors_origin_list(self) -> list[str]:
        """Parse comma-separated CORS origins."""
        if not self.cors_origins:
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]
