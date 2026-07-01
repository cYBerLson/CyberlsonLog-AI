"""
app/feature_engineering.py – Feature Engineering for Anomaly Detection
========================================================================
Transforms raw parsed log DataFrame into numerical features suitable for
the Isolation Forest anomaly detection model.

Features extracted per time window and per IP:
  - Event frequency (request rate)
  - Failed authentication count
  - HTTP error rate
  - Unique path diversity (entropy proxy)
  - Burst detection (inter-event time standard deviation)
  - Suspicious keyword flag rate
  - Hour-of-day (captures off-hours activity)

No external calls; purely Pandas/NumPy transformations.
"""

import numpy as np
import pandas as pd
import logging

logger = logging.getLogger(__name__)

# Time window for aggregation (minutes)
# A 5-minute window balances granularity vs. noise.
WINDOW_MINUTES = 5


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build feature matrix from parsed log DataFrame.

    Args:
        df: Output of log_parser.parse_log_file()

    Returns:
        feature_df: One row per (ip, time_window) with numerical feature columns.
                    Also includes 'timestamp_window' and 'ip' for display.
    """
    if df.empty:
        raise ValueError("Cannot engineer features from an empty DataFrame.")

    df = df.copy()

    # ── Time Window Bucketing ─────────────────────────────────────────────────
    # Round timestamps to WINDOW_MINUTES intervals for aggregation.
    df["timestamp_window"] = df["timestamp"].dt.floor(f"{WINDOW_MINUTES}min")
    df["hour"] = df["timestamp"].dt.hour

    # ── IP-Level Features (aggregated per IP across entire log) ───────────────
    ip_stats = (
        df.groupby("ip")
        .agg(
            ip_total_requests=("ip", "count"),
            ip_failed_auth_total=("is_failed_auth", "sum"),
            ip_suspicious_total=("is_suspicious", "sum"),
        )
        .reset_index()
    )

    # ── Window-Level Features ─────────────────────────────────────────────────
    agg_df = (
        df.groupby(["timestamp_window", "ip"])
        .agg(
            event_count=("message", "count"),
            failed_auth_count=("is_failed_auth", "sum"),
            suspicious_count=("is_suspicious", "sum"),
            unique_event_types=("event_type", "nunique"),
            error_4xx_count=("status_code", lambda x: ((x >= 400) & (x < 500)).sum()),
            error_5xx_count=("status_code", lambda x: (x >= 500).sum()),
            mean_status=("status_code", "mean"),
            hour=("hour", "first"),
        )
        .reset_index()
    )

    # ── Merge IP-Level Context ─────────────────────────────────────────────────
    agg_df = agg_df.merge(ip_stats, on="ip", how="left")

    # ── Derived Ratio Features ─────────────────────────────────────────────────
    # Failed-auth rate: proportion of events that are failed authentications
    agg_df["failed_auth_rate"] = agg_df["failed_auth_count"] / agg_df["event_count"].clip(lower=1)

    # Error rate: proportion of 4xx/5xx responses
    agg_df["http_error_rate"] = (
        (agg_df["error_4xx_count"] + agg_df["error_5xx_count"]) / agg_df["event_count"].clip(lower=1)
    )

    # Suspicious event rate
    agg_df["suspicious_rate"] = agg_df["suspicious_count"] / agg_df["event_count"].clip(lower=1)

    # Off-hours indicator: flag windows between 22:00 and 06:00
    # Off-hours activity is a meaningful anomaly signal in enterprise environments.
    agg_df["is_off_hours"] = agg_df["hour"].apply(
        lambda h: 1 if (h >= 22 or h <= 6) else 0
    ).astype(float)

    # Request burst flag: event count in window > 2 std deviations above mean
    mean_events = agg_df["event_count"].mean()
    std_events = agg_df["event_count"].std() or 1.0
    agg_df["is_burst"] = (agg_df["event_count"] > mean_events + 2 * std_events).astype(float)

    # IP repeat offender: IPs with many total failed auths get a higher weight
    agg_df["ip_failed_auth_weight"] = np.log1p(agg_df["ip_failed_auth_total"])
    agg_df["ip_suspicious_weight"] = np.log1p(agg_df["ip_suspicious_total"])

    # Log-transform event count (reduces effect of extreme outliers on model)
    agg_df["log_event_count"] = np.log1p(agg_df["event_count"])

    logger.info(
        "Feature engineering complete: %d windows across %d unique IPs",
        len(agg_df),
        agg_df["ip"].nunique(),
    )

    return agg_df


# Columns used as input to the ML model.
# This list is exported so anomaly_model.py and risk_engine.py use the same set.
FEATURE_COLUMNS = [
    "log_event_count",
    "failed_auth_count",
    "failed_auth_rate",
    "suspicious_count",
    "suspicious_rate",
    "http_error_rate",
    "unique_event_types",
    "is_off_hours",
    "is_burst",
    "ip_failed_auth_weight",
    "ip_suspicious_weight",
    "mean_status",
]
