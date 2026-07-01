"""
app/__init__.py – Flask Application Factory
=============================================
Uses the Application Factory pattern for testability and flexibility.
Applies security headers on every response to mitigate common web attacks.
"""

import os
from flask import Flask
from config import active_config


def create_app(config=None):
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    # ── Load Configuration ─────────────────────────────────────────────────────
    app.config.from_object(config or active_config)

    # ── Ensure Upload & Report Directories Exist ───────────────────────────────
    # Create directories safely; never trust that they exist.
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)

    # ── Register Routes ────────────────────────────────────────────────────────
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    # ── Security Headers Middleware ────────────────────────────────────────────
    # Applied to EVERY response. These headers defend against:
    #   X-Content-Type-Options        → MIME sniffing attacks
    #   X-Frame-Options               → Clickjacking
    #   X-XSS-Protection              → Legacy XSS filter (belt-and-suspenders)
    #   Content-Security-Policy       → XSS and data injection
    #   Referrer-Policy               → Information leakage via Referer header
    #   Permissions-Policy            → Disables unnecessary browser features
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # CSP: allow scripts/styles only from self and specific CDNs used in templates
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.plot.ly https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        # Disable caching for sensitive analysis pages
        if response.content_type and "text/html" in response.content_type:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response

    return app
