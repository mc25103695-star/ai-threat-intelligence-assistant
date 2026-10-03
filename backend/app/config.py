"""
AI Threat Intelligence Assistant - Configuration Module

Loads environment variables from .env file and exposes them
as a centralized Settings object. All API keys and config
values are accessed through this module — never hardcoded.

Usage:
    from app.config import settings
    key = settings.GEMINI_API_KEY

Validation:
    Call settings.validate() at startup to check that all
    required API keys are present. Missing keys are logged
    as warnings so the server still starts (useful during
    development when you may not have every key yet).
"""

import os
import logging
from dotenv import load_dotenv

# ============================================================
# Load .env file from the backend/ directory
# ============================================================
load_dotenv()

# ============================================================
# Logger for config-related messages
# ============================================================
logger = logging.getLogger("app.config")


class Settings:
    """
    Centralized configuration. Reads values from environment
    variables with sensible defaults where appropriate.

    Attributes:
        GEMINI_API_KEY      : Google Gemini API key for AI analysis
        GEMINI_MODEL        : Gemini model name (configurable via .env)
        VIRUSTOTAL_API_KEY  : VirusTotal API key for threat intelligence
        ABUSEIPDB_API_KEY   : AbuseIPDB API key for abuse/reputation data
        APP_NAME            : Display name of the application
        APP_VERSION         : Semantic version string
        DEBUG               : Enable debug mode (verbose logging)
    """

    # ---- API Keys ----
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

    # ---- Gemini Model Configuration ----
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    # ---- Application Settings ----
    APP_NAME: str = "AI Threat Intelligence Assistant"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # ---- Required keys and where to get them ----
    _REQUIRED_KEYS = {
        "GEMINI_API_KEY": "https://aistudio.google.com/apikey",
        "VIRUSTOTAL_API_KEY": "https://www.virustotal.com/gui/join-us",
        "ABUSEIPDB_API_KEY": "https://www.abuseipdb.com/account/api",
    }

    def validate(self) -> dict:
        """
        Check which API keys are configured and which are missing.

        Returns a dict like:
            {
                "configured": ["GEMINI_API_KEY"],
                "missing": ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]
            }

        Missing keys are logged as warnings but do NOT crash the
        server, so you can develop incrementally (e.g., test
        VirusTotal before you have a Gemini key).
        """
        configured = []
        missing = []

        for key_name, signup_url in self._REQUIRED_KEYS.items():
            value = getattr(self, key_name, "")
            if value and value.strip():
                configured.append(key_name)
                logger.info("✅ %s is configured.", key_name)
            else:
                missing.append(key_name)
                logger.warning(
                    "⚠️  %s is NOT set. Get your key at: %s",
                    key_name,
                    signup_url,
                )

        if not missing:
            logger.info("🎉 All API keys are configured!")
        else:
            logger.warning(
                "🔑 %d of %d API keys are missing. "
                "Some features will be unavailable until they are set in .env",
                len(missing),
                len(self._REQUIRED_KEYS),
            )

        # Log active Gemini model
        logger.info("🤖 Active Gemini model: %s", self.GEMINI_MODEL)

        return {"configured": configured, "missing": missing}


# ============================================================
# Singleton instance — import this everywhere
# ============================================================
settings = Settings()
