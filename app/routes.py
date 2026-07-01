"""
app/routes.py – Flask Route Handlers
======================================
Implements all HTTP endpoints for CyberlsonShield.

Security controls applied at every route:
  - File extension whitelist (ALLOWED_EXTENSIONS)
  - Secure filename via werkzeug.utils.secure_filename (prevents path traversal)
  - File size limit enforced by Flask MAX_CONTENT_LENGTH
  - Input validation before processing
  - Temporary files cleaned up after use
  - No user-controlled path components in file operations
  - Errors are caught and returned as generic messages (no stack trace leakage)
"""

import os
import uuid
import logging
import json
from datetime import datetime, timezone

from flask import (
    Blueprint, render_template, request, jsonify,
    send_file, current_app, abort
)
from werkzeug.utils import secure_filename

from app.log_parser import parse_log_file
from app.feature_engineering import engineer_features
from app.anomaly_model import run_anomaly_detection
from app.risk_engine import compute_system_risk, build_findings, generate_pdf_report

main_bp = Blueprint("main", __name__)
logger = logging.getLogger(__name__)


def _allowed_file(filename: str) -> bool:
    """
    Validate file extension against the configured whitelist.
    Returns False if filename has no extension or an unsupported one.
    """
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def _safe_upload_path(filename: str) -> str:
    """
    Generate a safe absolute path for the uploaded file.

    Uses werkzeug.utils.secure_filename to strip directory separators,
    null bytes, and other dangerous characters from the filename.
    Prepends a UUID to prevent filename collisions and guessing.
    """
    safe_name = secure_filename(filename)
    if not safe_name:
        safe_name = "upload.log"
    # Prepend UUID to avoid collisions and prevent filename-based attacks
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    return os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)


# ── Routes ─────────────────────────────────────────────────────────────────────
@main_bp.route("/")
def index():
    import os
    print("CURRENT TEMPLATE:", os.path.abspath("../templates/index.html"))
    return render_template("index.html")


@main_bp.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /analyze – Accept log file upload and run full analysis pipeline.

    Pipeline:
      1. Validate file (extension, size)
      2. Save to secure upload directory
      3. Parse log → DataFrame
      4. Engineer features
      5. Run Isolation Forest anomaly detection
      6. Compute system risk score
      7. Build findings
      8. Return JSON results (no file path exposed to client)
    """
    # ── Step 1: File Presence Check ────────────────────────────────────────────
    if "logfile" not in request.files:
        return jsonify({"error": "No file uploaded. Please select a .log or .txt file."}), 400

    file = request.files["logfile"]

    if not file or file.filename == "":
        return jsonify({"error": "Empty filename. Please select a file."}), 400

    # ── Step 2: Extension Validation ───────────────────────────────────────────
    if not _allowed_file(file.filename):
        return jsonify({
            "error": "Invalid file type. Only .log and .txt files are accepted."
        }), 400

    # ── Step 3: Save File Securely ─────────────────────────────────────────────
    filepath = _safe_upload_path(file.filename)
    try:
        file.save(filepath)
        logger.info("File saved: %s", os.path.basename(filepath))
    except OSError as exc:
        logger.error("File save failed: %s", exc)
        return jsonify({"error": "Failed to save uploaded file. Please try again."}), 500

    # ── Step 4–8: Analysis Pipeline ────────────────────────────────────────────
    try:
        # Parse
        df = parse_log_file(filepath)

        print("=" * 60)
        print("DATAFRAME AFTER PARSING")
        print(df.head())
        print(df.info())
        print(df.columns.tolist())
        print("Rows:", len(df))
        print("=" * 60)

        # Feature Engineering
        feature_df = engineer_features(df)

        # Anomaly Detection
        result_df = run_anomaly_detection(feature_df)

        # Risk Scoring
        risk_result = compute_system_risk(result_df)

        # Findings
        findings = build_findings(result_df)

        # ── Serialize for JSON ─────────────────────────────────────────────────
        # Convert pandas/numpy types to native Python for JSON serialization.
        response_data = {
            "risk": {
                "score": float(risk_result["score"]),
                "tier": risk_result["tier"],
                "color": risk_result["color"],
                "components": {k: float(v) for k, v in risk_result["components"].items()},
            },
            "summary": {k: int(v) if isinstance(v, (int, float)) else v
                        for k, v in findings["summary"].items()},
            "timeline": findings["timeline"],
            "top_suspicious_ips": [
                {k: (float(v) if isinstance(v, float) else
                     int(v) if hasattr(v, 'item') else v)
                 for k, v in rec.items()}
                for rec in findings["top_suspicious_ips"]
            ],
            "recommendations": findings["recommendations"],
            "analyzed_at": datetime.now(tz=timezone.utc).isoformat(),
            # Store upload path in server-side session proxy via a report token
            "_upload_ref": os.path.basename(filepath),
        }

        return jsonify(response_data), 200

    except ValueError as exc:
        # Known validation errors (empty file, unrecognised format) → 400
        logger.warning("Analysis validation error: %s", exc)
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        # Unexpected errors → 500, but don't leak stack traces to client
        logger.exception("Unexpected analysis error")
        return jsonify({"error": "Analysis failed due to an internal error. Please try again."}), 500
    finally:
        # ── Cleanup: Delete uploaded file after analysis ────────────────────────
        # Never retain uploaded files longer than needed.
        # This reduces data exposure risk and storage overhead.
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.debug("Cleaned up upload: %s", os.path.basename(filepath))
        except OSError:
            pass  # Non-critical; log and continue


@main_bp.route("/report", methods=["POST"])
def generate_report():
    """
    POST /report – Generate and return a downloadable PDF report.

    Expects JSON body with the same analysis results returned by /analyze.
    Report is generated on-the-fly from submitted data; no server-side state needed.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    try:
        risk_result = data.get("risk", {})
        findings = {
            "summary": data.get("summary", {}),
            "timeline": data.get("timeline", []),
            "top_suspicious_ips": data.get("top_suspicious_ips", []),
            "recommendations": data.get("recommendations", []),
        }

        report_path = generate_pdf_report(
            findings=findings,
            risk_result=risk_result,
            report_folder=current_app.config["REPORT_FOLDER"],
        )

        # Send file to client, then delete from server
        response = send_file(
            report_path,
            as_attachment=True,
            download_name=os.path.basename(report_path),
            mimetype="application/pdf",
        )

        # Schedule cleanup after sending
        @response.call_on_close
        def cleanup():
            try:
                if os.path.exists(report_path):
                    os.remove(report_path)
            except OSError:
                pass

        return response

    except Exception:
        logger.exception("Report generation failed")
        return jsonify({"error": "Report generation failed. Please try again."}), 500


@main_bp.route("/health")
def health():
    """Health check endpoint for load balancers and monitoring."""
    return jsonify({"status": "ok", "service": "CyberlsonShield"}), 200


@main_bp.errorhandler(413)
def request_entity_too_large(error):
    """Handle file-too-large errors gracefully."""
    return jsonify({
        "error": f"File too large. Maximum size is {current_app.config['MAX_CONTENT_LENGTH'] // (1024*1024)} MB."
    }), 413


@main_bp.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found."}), 404


@main_bp.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed."}), 405
