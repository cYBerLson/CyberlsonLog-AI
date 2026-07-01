"""
app/risk_engine.py – Risk Scoring Engine & Report Generator
=============================================================
Combines ML anomaly scores with rule-based heuristics to produce:
  1. A composite system risk score (0–100)
  2. A risk tier (Low / Medium / High / Critical)
  3. Structured findings suitable for the dashboard and PDF report
  4. Defensive recommendations based on detected patterns

The hybrid approach (ML + rules) reduces false negatives: the model
catches statistical deviations while rules enforce known-bad signatures.
"""

import logging
import os
from datetime import datetime, timezone

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    Image,
)

logger = logging.getLogger(__name__)
# --------------------------------------------------------
# Logo Path
# --------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOGO_PATH = os.path.join(
    BASE_DIR,
    "static",
    "img",
    "shield.png"
)


# ── Risk Tier Thresholds ───────────────────────────────────────────────────────
RISK_TIERS = [
    (80, "Critical",  "#dc2626"),
    (60, "High",      "#ea580c"),
    (35, "Medium",    "#d97706"),
    (0,  "Low",       "#16a34a"),
]


def compute_system_risk(result_df: pd.DataFrame) -> dict:
    """
    Derive a single composite risk score from the annotated anomaly DataFrame.

    Scoring components:
      - Base score from mean anomaly score of flagged windows (40%)
      - Failed authentication severity (25%)
      - Suspicious event concentration (20%)
      - Off-hours activity presence (15%)

    Returns a dict with score, tier, color, and component breakdown.
    """
    if result_df.empty:
        return {"score": 0, "tier": "Low", "color": "#16a34a", "components": {}}

    total = len(result_df)
    flagged = result_df[result_df["is_anomaly"]]

    # Component 1: Mean anomaly score of flagged windows
    mean_anomaly = flagged["anomaly_score"].mean() if len(flagged) else 0.0

    # Component 2: Failed auth density across ALL windows
    total_failed = result_df["failed_auth_count"].sum()
    total_events = result_df["event_count"].sum() if "event_count" in result_df.columns else 1
    failed_auth_density = min(total_failed / max(total_events, 1), 1.0)

    # Component 3: Suspicious event proportion
    total_suspicious = result_df.get("suspicious_count", pd.Series([0])).sum()
    suspicious_density = min(total_suspicious / max(total_events, 1), 1.0)

    # Component 4: Off-hours anomaly proportion
    off_hours_anomaly_frac = (
        (flagged["is_off_hours"] == 1).sum() / max(len(flagged), 1)
        if len(flagged) else 0.0
    )

    # Weighted composite (weights sum to 1.0)
    composite = (
        0.40 * mean_anomaly
        + 0.25 * failed_auth_density
        + 0.20 * suspicious_density
        + 0.15 * off_hours_anomaly_frac
    )

    # Scale to 0–100
    score = round(min(composite * 100, 100), 1)

    # Determine tier
    tier, color = "Low", "#16a34a"
    for threshold, name, hex_color in RISK_TIERS:
        if score >= threshold:
            tier, color = name, hex_color
            break

    components = {
        "ml_anomaly_component": round(mean_anomaly * 100, 1),
        "failed_auth_component": round(failed_auth_density * 100, 1),
        "suspicious_events_component": round(suspicious_density * 100, 1),
        "off_hours_component": round(off_hours_anomaly_frac * 100, 1),
    }

    logger.info("System risk score: %.1f (%s)", score, tier)
    return {"score": score, "tier": tier, "color": color, "components": components}


def build_findings(result_df: pd.DataFrame) -> dict:
    """
    Extract structured findings for the dashboard and report.

    Returns:
      - top_suspicious_ips: list of {ip, risk_label, anomaly_score, failed_auth, explanation}
      - timeline: list of {window, score, label} for chart
      - summary_stats: aggregate statistics
      - recommendations: list of defensive recommendations
    """
    df = result_df.copy()

    # ── Top Suspicious IPs ─────────────────────────────────────────────────────
    ip_risk = (
        df.groupby("ip")
        .agg(
            max_anomaly_score=("anomaly_score", "max"),
            total_failed_auth=("failed_auth_count", "sum"),
            total_suspicious=("suspicious_count", "sum"),
            event_windows=("event_count", "count"),
            any_anomaly=("is_anomaly", "any"),
        )
        .reset_index()
        .sort_values("max_anomaly_score", ascending=False)
    )

    # Assign per-IP risk labels
    def ip_label(score):
        if score >= 0.65:
            return "High Risk"
        elif score >= 0.35:
            return "Suspicious"
        return "Normal"

    ip_risk["risk_label"] = ip_risk["max_anomaly_score"].apply(ip_label)

    # Merge in the best explanation per IP
    top_explanation_per_ip = (
        df.sort_values("anomaly_score", ascending=False)
        .groupby("ip")["explanation"]
        .first()
        .reset_index()
    )
    ip_risk = ip_risk.merge(top_explanation_per_ip, on="ip", how="left")

    top_ips = ip_risk.head(10).to_dict(orient="records")
    for rec in top_ips:
        rec["max_anomaly_score"] = round(float(rec["max_anomaly_score"]), 3)

    # ── Timeline Data ──────────────────────────────────────────────────────────
    timeline_df = (
        df.groupby("timestamp_window")
        .agg(
            max_score=("anomaly_score", "max"),
            mean_score=("anomaly_score", "mean"),
            anomaly_count=("is_anomaly", "sum"),
            total_failed_auth=("failed_auth_count", "sum"),
        )
        .reset_index()
        .sort_values("timestamp_window")
    )
    timeline = []
    for _, row in timeline_df.iterrows():
        timeline.append({
            "window": row["timestamp_window"].strftime("%Y-%m-%d %H:%M"),
            "max_score": round(float(row["max_score"]), 3),
            "mean_score": round(float(row["mean_score"]), 3),
            "anomaly_count": int(row["anomaly_count"]),
            "failed_auth": int(row["total_failed_auth"]),
        })

    # ── Summary Statistics ─────────────────────────────────────────────────────
    summary = {
        "total_log_entries": int(df["event_count"].sum()) if "event_count" in df.columns else len(df),
        "total_time_windows": len(df),
        "anomalous_windows": int(df["is_anomaly"].sum()),
        "high_risk_windows": int((df["risk_label"] == "High Risk").sum()),
        "suspicious_windows": int((df["risk_label"] == "Suspicious").sum()),
        "unique_ips": df["ip"].nunique(),
        "total_failed_auth": int(df["failed_auth_count"].sum()),
        "total_suspicious_events": int(df.get("suspicious_count", pd.Series([0])).sum()),
    }

    # ── Defensive Recommendations ─────────────────────────────────────────────
    recommendations = _generate_recommendations(df, summary)

    return {
        "top_suspicious_ips": top_ips,
        "timeline": timeline,
        "summary": summary,
        "recommendations": recommendations,
    }


def _generate_recommendations(df: pd.DataFrame, summary: dict) -> list[dict]:
    """
    Rule-based defensive recommendation engine.
    Maps detected patterns to actionable defensive guidance.
    All recommendations are strictly defensive (monitoring, blocking, hardening).
    """
    recs = []

    if summary["total_failed_auth"] >= 10:
        recs.append({
            "priority": "High",
            "category": "Authentication Hardening",
            "finding": f"{summary['total_failed_auth']} failed authentication events detected.",
            "action": (
                "Implement account lockout policies (e.g., lock after 5 failures). "
                "Enable multi-factor authentication (MFA) for all privileged accounts. "
                "Review auth logs with `journalctl -u sshd` or equivalent. "
                "Consider deploying fail2ban to auto-block repeat offenders."
            ),
        })

    if summary["total_suspicious_events"] >= 5:
        recs.append({
            "priority": "High",
            "category": "Web Application Firewall (WAF)",
            "finding": f"{summary['total_suspicious_events']} events contained suspicious patterns (SQL, path traversal, etc.).",
            "action": (
                "Deploy a WAF (e.g., ModSecurity with OWASP CRS) in front of web services. "
                "Audit application input validation. "
                "Enable OWASP Core Rule Set blocking mode. "
                "Conduct a targeted code review of endpoints flagged in the log."
            ),
        })

    high_risk_ips = [r for r in df.groupby("ip")["anomaly_score"].max().reset_index().to_dict("records")
                     if r["anomaly_score"] >= 0.65]
    if high_risk_ips:
        ip_list = ", ".join(r["ip"] for r in high_risk_ips[:5])
        recs.append({
            "priority": "High",
            "category": "IP Threat Response",
            "finding": f"IPs with sustained high-risk scores: {ip_list}",
            "action": (
                "Block flagged IPs at the firewall/security group level immediately. "
                "Cross-reference against threat intelligence feeds (e.g., AbuseIPDB, Shodan). "
                "Preserve log evidence for potential incident response. "
                "Monitor lateral movement from these IPs across other systems."
            ),
        })

    off_hours = df[df["is_off_hours"] == 1]
    if len(off_hours) > 0 and off_hours["is_anomaly"].any():
        recs.append({
            "priority": "Medium",
            "category": "After-Hours Activity Monitoring",
            "finding": "Anomalous activity detected during off-hours (10 PM – 6 AM).",
            "action": (
                "Set up SIEM alerting for off-hours access to sensitive systems. "
                "Implement time-based access controls for non-essential accounts. "
                "Review whether the off-hours activity aligns with scheduled jobs or maintenance windows."
            ),
        })

    if summary["anomalous_windows"] == 0:
        recs.append({
            "priority": "Low",
            "category": "Ongoing Monitoring",
            "finding": "No anomalies detected in this log sample.",
            "action": (
                "Continue regular log ingestion and analysis. "
                "Establish a baseline by running CyberlsonLog AI on 30+ days of logs. "
                "Integrate with a SIEM for real-time alerting."
            ),
        })

    recs.append({
        "priority": "Medium",
        "category": "Log Hygiene & Retention",
        "finding": "General best practice.",
        "action": (
            "Ensure logs are forwarded to a tamper-evident, centralized log management system. "
            "Retain logs for at least 90 days (or as required by compliance frameworks). "
            "Enable log integrity checking (e.g., auditd, immutable log flags)."
        ),
    })

    return recs


def generate_pdf_report(
    findings: dict,
    risk_result: dict,
    report_folder: str,
    filename: str = None,
) -> str:
    """
    Generate a professional PDF threat analysis report using ReportLab.

    Args:
        findings:      Output of build_findings()
        risk_result:   Output of compute_system_risk()
        report_folder: Absolute path to the reports directory
        filename:      Optional output filename (auto-generated if None)

    Returns:
        Absolute path to the generated PDF file.
    """
    if not filename:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"CyberlsonLog_AI_Threat_Report_{ts}.pdf"

    # Sanitize filename: only allow alphanumeric, underscore, hyphen, dot
    import re
    filename = re.sub(r"[^a-zA-Z0-9_\-.]", "_", filename)
    if not filename.endswith(".pdf"):
        filename += ".pdf"

    output_path = os.path.join(report_folder, filename)

    # ── Document Setup ─────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=22,
        textColor=colors.HexColor("#0f172a"), spaceAfter=8,
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=14,
        textColor=colors.HexColor("#1e40af"), spaceBefore=14, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontName="Helvetica", fontSize=10,
        textColor=colors.HexColor("#1e293b"), leading=14, spaceAfter=6,
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["Normal"],
        fontName="Helvetica", fontSize=8,
        textColor=colors.HexColor("#64748b"), leading=11,
    )

    story = []
    story = []
    summary = findings["summary"]
    tier_colors = {
        "Critical": "#dc2626", "High": "#ea580c",
        "Medium": "#d97706", "Low": "#16a34a",
    }
    tier_color = tier_colors.get(risk_result["tier"], "#1e40af")

    # ── Title Page ─────────────────────────────────────────────────────────────
    story.append(
        Paragraph(
            "CyberlsonLog AI<br/><font size='16'>Intelligent Log Threat Analysis Report</font>",
            title_style,
        )
    )
    story.append(
        Paragraph(
            f"Generated: {datetime.now(tz=timezone.utc).strftime('%B %d, %Y at %H:%M UTC')} | "
            f"Classification: <b>INTERNAL USE ONLY</b>",
            small_style
        )
    )
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e40af")))
    story.append(Spacer(1, 0.4 * cm))

    # ── Risk Score Banner ──────────────────────────────────────────────────────
    risk_data = [[
        Paragraph(f"<b>Overall System Risk Score</b>", body_style),
        Paragraph(
            f"<b><font color='{tier_color}'>{risk_result['score']} / 100 — {risk_result['tier']}</font></b>",
            ParagraphStyle("RiskScore", parent=body_style, fontSize=16)
        ),
    ]]
    risk_table = Table(risk_data, colWidths=["50%", "50%"])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#1e40af")),
        ("INNERGRID", (0, 0), (-1, -1), 0, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_style))
    story.append(Paragraph(
        f"CyberlsonLog AI analyzed <b>{summary['total_time_windows']}</b> time windows covering approximately "
        f"<b>{summary['total_log_entries']:,}</b> log events from <b>{summary['unique_ips']}</b> unique IP addresses. "
        f"The Isolation Forest model flagged <b>{summary['anomalous_windows']}</b> windows as anomalous, "
        f"of which <b>{summary['high_risk_windows']}</b> were classified as <font color='#dc2626'><b>High Risk</b></font> "
        f"and <b>{summary['suspicious_windows']}</b> as <font color='#d97706'><b>Suspicious</b></font>. "
        f"A total of <b>{summary['total_failed_auth']}</b> failed authentication events and "
        f"<b>{summary['total_suspicious_events']}</b> events with suspicious patterns were observed.",
        body_style
    ))
    story.append(Spacer(1, 0.3 * cm))

    # ── Key Metrics Table ──────────────────────────────────────────────────────
    story.append(Paragraph("Key Metrics", h2_style))
    metrics_data = [
        ["Metric", "Value"],
        ["Total Log Events Analyzed", f"{summary['total_log_entries']:,}"],
        ["Time Windows Analyzed", str(summary["total_time_windows"])],
        ["Unique IP Addresses", str(summary["unique_ips"])],
        ["Anomalous Windows", str(summary["anomalous_windows"])],
        ["High Risk Windows", str(summary["high_risk_windows"])],
        ["Suspicious Windows", str(summary["suspicious_windows"])],
        ["Failed Auth Events", str(summary["total_failed_auth"])],
        ["Suspicious Pattern Events", str(summary["total_suspicious_events"])],
    ]
    metrics_table = Table(metrics_data, colWidths=["65%", "35%"])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Top Suspicious IPs ─────────────────────────────────────────────────────
    story.append(Paragraph("Top Suspicious IP Addresses", h2_style))
    ip_data = [["IP Address", "Risk Label", "Anomaly Score", "Failed Auth", "Finding"]]
    label_colors = {"High Risk": "#dc2626", "Suspicious": "#d97706", "Normal": "#16a34a"}

    for rec in findings["top_suspicious_ips"][:8]:
        lbl = rec.get("risk_label", "Normal")
        lbl_color = label_colors.get(lbl, "#1e293b")
        ip_data.append([
            Paragraph(f"<b>{rec['ip']}</b>", body_style),
            Paragraph(f"<font color='{lbl_color}'><b>{lbl}</b></font>", body_style),
            f"{rec['max_anomaly_score']:.3f}",
            str(int(rec.get("total_failed_auth", 0))),
            Paragraph(rec.get("explanation", "")[:120], small_style),
        ])

    ip_table = Table(ip_data, colWidths=["18%", "14%", "12%", "10%", "46%"])
    ip_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(ip_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Recommendations ────────────────────────────────────────────────────────
    story.append(Paragraph("Defensive Recommendations", h2_style))
    prio_colors = {"High": "#dc2626", "Medium": "#d97706", "Low": "#16a34a"}

    for i, rec in enumerate(findings["recommendations"], 1):
        pc = prio_colors.get(rec["priority"], "#1e293b")
        story.append(Paragraph(
            f"<b>{i}. [{rec['category']}]</b> "
            f"— Priority: <font color='{pc}'><b>{rec['priority']}</b></font>",
            body_style
        ))
        story.append(Paragraph(f"<i>Finding:</i> {rec['finding']}", small_style))
        story.append(Paragraph(f"<b>Action:</b> {rec['action']}", body_style))
        story.append(Spacer(1, 0.2 * cm))

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94a3b8")))
    story.append(
        Paragraph(
            "<b>CyberlsonLog AI</b><br/>"
            "AI-Powered Log Anomaly Detection Platform<br/><br/>"
            "This report was automatically generated using Machine Learning "
            "(Isolation Forest), statistical anomaly detection and defensive "
            "cybersecurity analytics.<br/><br/>"
            "Purpose: Defensive Security Operations Only.<br/>"
            "No uploaded log files are stored after analysis.",
            small_style,
        )
    )

    # Build PDF
    doc.build(
        story,
        onFirstPage=add_logo,
        onLaterPages=add_logo,
    )

    logger.info("PDF report generated: %s", output_path)
    return output_path


def add_logo(canvas, doc):
    """
    Draw CyberlsonLog AI logo on every PDF page.
    """
    if os.path.exists(LOGO_PATH):
        logo = ImageReader(LOGO_PATH)

        canvas.drawImage(
            logo,
            doc.leftMargin,
            A4[1] - 2.3 * cm,
            width=1.4 * cm,
            height=1.4 * cm,
            preserveAspectRatio=True,
            mask="auto",
        )

    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(
        doc.leftMargin + 1.8 * cm,
        A4[1] - 1.65 * cm,
        "CyberlsonLog AI"
    )

    # solely draw logo/header on each page
    return None
