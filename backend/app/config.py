"""Backend configuration via environment variables."""
from __future__ import annotations

import os

try:
    from pydantic_settings import BaseSettings

    class Settings(BaseSettings):
        app_name: str = "Prahari API"
        supabase_url: str = ""                    # empty -> local in-memory mode
        supabase_service_role_key: str = ""
        max_upload_mb: int = 25
        cors_origins: str = ("http://localhost:3000,http://localhost:4000,"
                             "http://localhost:4567")
        max_concurrent_analyses: int = 2

        @property
        def cors_origin_list(self) -> list[str]:
            """Explicit origins only — '*' is rejected: the site is public,
            so a wildcard origin list would invite abuse."""
            origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
            return [o for o in origins if o != "*"]
except ImportError:                                    # pragma: no cover
    class Settings:                                    # type: ignore[no-redef]
        def __init__(self) -> None:
            self.app_name = os.environ.get("APP_NAME", "Prahari API")
            self.supabase_url = os.environ.get("SUPABASE_URL", "")
            self.supabase_service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
            self.max_upload_mb = int(os.environ.get("MAX_UPLOAD_MB", "25"))
            self.cors_origins = os.environ.get(
                "CORS_ORIGINS",
                "http://localhost:3000,http://localhost:4000,http://localhost:4567")
            self.max_concurrent_analyses = int(
                os.environ.get("MAX_CONCURRENT_ANALYSES", "2"))

        @property
        def cors_origin_list(self) -> list[str]:
            origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
            return [o for o in origins if o != "*"]


settings = Settings()
