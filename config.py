"""
config.py – CyberlsonLog AI Configuration
=========================================
Central configuration for CyberlsonLog AI.

Loads all sensitive settings from environment variables.
Never hardcodes secrets and follows security best practices,
including OWASP Top 10 recommendations for secure configuration.
"""

import os
from dotenv import load_dotenv

# Load .env file if present (for local development only)
load_dotenv()


class Config:
    # ── Security ──────────────────────────────────────────────────────────────
    # SECRET_KEY must be set via environment variable in production.
    # Flask uses this to sign session cookies. A missing/weak key is a critical
    # security flaw (OWASP A07: Identification and Authentication Failures).
    SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is required. "
        "Copy .env.example to .env for local development."
    )
 

    # ── File Upload Security ───────────────────────────────────────────────────
    # Restrict accepted extensions to prevent upload of executable or dangerous
    # file types (OWASP A03: Injection / unrestricted file upload).
    ALLOWED_EXTENSIONS = {"log", "txt"}

    # Hard cap on upload size: 10 MB.
    # Prevents denial-of-service via large file upload.
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

    # Upload directory is explicitly set and isolated from application code.
    # Never allow user-controlled paths (prevents path traversal – OWASP A01).
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")

    REPORT_FOLDER = os.path.join(os.path.dirname(__file__), "reports")

    # ── Flask Settings ─────────────────────────────────────────────────────────
    # Debug mode MUST be False in production. Debug exposes the Werkzeug
    # interactive debugger which allows arbitrary code execution.
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    TESTING = False

    # ── Rate Limiting ──────────────────────────────────────────────────────────
    # Prevent brute-force or abuse of the upload endpoint.
    RATELIMIT_DEFAULT = "30 per minute"
    RATELIMIT_STORAGE_URL = "memory://"


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False


class DevelopmentConfig(Config):
    DEBUG = True


# Select config based on environment variable
config_map = {
    "production": ProductionConfig,
    "development": DevelopmentConfig,
}

active_config = config_map.get(
    os.environ.get("FLASK_ENV", "development"), DevelopmentConfig
)
