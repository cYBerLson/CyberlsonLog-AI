"""
run.py – CyberlsonLog AI Application Entry Point
=============================================
For development: python run.py
For production: gunicorn --config gunicorn.conf.py run:application
"""

import logging
import os
from app import create_app

# ── Logging Configuration ──────────────────────────────────────────────────────
# Structured logging to stdout; production deployments should forward
# stdout to a centralized log aggregator (e.g., Loki, Splunk, CloudWatch).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

# ── Create Application ─────────────────────────────────────────────────────────
application = create_app()  # Named 'application' for Gunicorn/uWSGI compatibility

if __name__ == "__main__":
    # NEVER set debug=True in production.
    # The FLASK_DEBUG env var controls this; see config.py.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port = int(os.environ.get("PORT", 5000))

    application.run(
        host="127.0.0.1",   # Bind to localhost only; Nginx proxies externally
        port=port,
        debug=debug_mode,
    )
