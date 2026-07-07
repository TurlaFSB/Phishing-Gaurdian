"""
============================================================================
PHISHING GUARDIAN — CORE CONFIGURATION
============================================================================
Centralized settings management using Pydantic.
All configuration from environment variables with sensible defaults.

Author:  Dr. Erik
Version: 1.0.0
License: MIT (Free for all uses)
============================================================================
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


# ---------------------------------------------------------------------------
# PROJECT PATHS
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"
DB_DIR = DATA_DIR / "db"
LOGS_DIR = ROOT_DIR / "logs"
REPORTS_DIR = ROOT_DIR / "reports"
ENV_FILE = ROOT_DIR / ".env"

# Ensure directories exist
for directory in [DATA_DIR, CACHE_DIR, DB_DIR, LOGS_DIR, REPORTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# SETTINGS CLASS
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All API keys are OPTIONAL — the tool works without them
    using completely free sources (PhishTank, OpenPhish, WHOIS, URLScan).
    """

    # --- APPLICATION ---
    APP_NAME: str = Field(default="Phishing Guardian")
    APP_VERSION: str = Field(default="1.0.0")
    APP_ENV: str = Field(default="development")
    APP_DEBUG: bool = Field(default=True)
    APP_HOST: str = Field(default="0.0.0.0")
    APP_PORT: int = Field(default=8000)

    # --- SECURITY ---
    SECRET_KEY: str = Field(default="change-this-to-a-random-secret-key-in-production")
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:8000", "http://127.0.0.1:8000"]
    )

    # --- FREE API KEYS (ALL OPTIONAL) ---
    VT_API_KEY: Optional[str] = Field(default=None)
    ABUSEIPDB_API_KEY: Optional[str] = Field(default=None)
    GSB_API_KEY: Optional[str] = Field(default=None)
    URLSCAN_API_KEY: Optional[str] = Field(default=None)

    # --- FREE API ENDPOINTS (NO KEY NEEDED) ---
    PHISHTANK_URL: str = Field(default="https://data.phishtank.com/data/online-valid.json")
    OPENPHISH_URL: str = Field(default="https://openphish.com/feed.txt")
    URLSCAN_BASE_URL: str = Field(default="https://urlscan.io/api/v1")

    # --- RATE LIMITING ---
    RATE_LIMIT_PER_MINUTE: int = Field(default=30)

    # --- CACHE ---
    CACHE_ENABLED: bool = Field(default=True)
    CACHE_TTL_HOURS: int = Field(default=24)
    CACHE_DIR: Path = Field(default=CACHE_DIR)

    # --- DATABASE ---
    DATABASE_URL: str = Field(default=f"sqlite+aiosqlite:///{DB_DIR}/phishing_guardian.db")

    # --- LOGGING ---
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FILE: str = Field(default=str(LOGS_DIR / "app.log"))

    # --- ANALYSIS LIMITS ---
    MAX_URLS_TO_ANALYZE: int = Field(default=20)
    MAX_IPS_TO_ANALYZE: int = Field(default=10)
    MAX_DOMAINS_TO_ANALYZE: int = Field(default=10)
    MAX_ATTACHMENT_SIZE_MB: int = Field(default=10)

    # --- RISK SCORING WEIGHTS ---
    WEIGHT_VIRUSTOTAL: float = Field(default=0.25)
    WEIGHT_URLSCAN: float = Field(default=0.15)
    WEIGHT_ABUSEIPDB: float = Field(default=0.10)
    WEIGHT_PHISHTANK: float = Field(default=0.20)
    WEIGHT_WHOIS: float = Field(default=0.15)
    WEIGHT_HEADERS: float = Field(default=0.15)

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.APP_ENV == "development"

    @property
    def available_apis(self) -> dict:
        """Return which APIs are configured."""
        return {
            "virustotal": bool(self.VT_API_KEY),
            "abuseipdb": bool(self.ABUSEIPDB_API_KEY),
            "googlesafebrowsing": bool(self.GSB_API_KEY),
            "urlscan": True,
            "phishtank": True,
            "openphish": True,
            "whois": True,
        }

    model_config = {
        "env_file": str(ENV_FILE),
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


# ---------------------------------------------------------------------------
# SINGLETON INSTANCE
# ---------------------------------------------------------------------------
settings = Settings()


# ---------------------------------------------------------------------------
# STARTUP VERIFICATION
# ---------------------------------------------------------------------------
def verify_configuration() -> dict:
    """
    Verify configuration on startup.
    Returns a report of what's configured and what's missing.
    """
    apis = settings.available_apis
    free_apis = [name for name, available in apis.items() if available]
    configured_apis = [
        name for name, available in apis.items()
        if available and getattr(settings, f"{name.upper()}_API_KEY", None)
    ]

    return {
        "total_apis_available": len(free_apis),
        "free_apis": free_apis,
        "apis_with_keys": configured_apis,
        "completely_free": ["phishtank", "openphish", "urlscan", "whois"],
        "status": "READY",
        "warning": None if len(free_apis) >= 4 else "Consider adding API keys for better analysis",
    }