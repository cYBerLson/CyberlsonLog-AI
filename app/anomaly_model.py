"""
app/anomaly_model.py – AI Anomaly Detection Engine
=====================================================
Uses scikit-learn's Isolation Forest for unsupervised anomaly detection.

Why Isolation Forest?
  - Works well on tabular log features with no labeled training data
  - Scales linearly with dataset size (O(n log n))
  - Naturally handles high-dimensional sparse feature spaces
  - Contamination parameter provides interpretable anomaly budget
  - Produces continuous anomaly scores for risk ranking

Design philosophy:
  - Model is trained fresh on each uploaded log batch (no stale state)
  - Feature matrix is standardized before training for consistent scaling
  - Anomaly scores are normalized to [0, 1] for the risk engine
  - Each flagged window has a plain-English explanation generated
"""

import numpy as np
import pandas as pd
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from app.feature_engineering import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# ── Model Hyperparameters ──────────────────────────────────────────────────────
# contamination: Expected fraction of anomalous windows in data.
# 0.05 = assume ~5% of time windows may contain anomalous activity.
# Tune upward for noisier environments.
CONTAMINATION = 0.05

# n_estimators: Number of isolation trees. More trees → more stable scores.
N_ESTIMATORS = 150

# max_samples: "auto" → use min(256, n_samples). Good for small log files.
MAX_SAMPLES = "auto"

# Random state for reproducibility across requests.
RANDOM_STATE = 42


def _normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
    """
    Isolation Forest returns negative scores where more negative = more anomalous.
    We invert and normalize to [0, 1] so higher score = higher anomaly risk.
    """
    # Invert sign: anomalies have higher values now
    inverted = -raw_scores
    min_val, max_val = inverted.min(), inverted.max()
    if max_val == min_val:
        return np.zeros_like(inverted)
    return (inverted - min_val) / (max_val - min_val)


def _generate_explanation(row: pd.Series) -> str:
    """
    Generate a plain-English explanation for why a window was flagged.
    This is the "explainable AI" component – making model decisions transparent.
    Purely rule-based on feature values; no black-box reasoning.
    """
    reasons = []

    if row.get("failed_auth_count", 0) >= 3:
        reasons.append(
            f"{int(row['failed_auth_count'])} failed authentication attempts in this window"
        )
    if row.get("failed_auth_rate", 0) > 0.5:
        reasons.append(
            f"High failed-auth rate ({row['failed_auth_rate']:.0%} of events)"
        )
    if row.get("suspicious_count", 0) > 0:
        reasons.append(
            f"{int(row['suspicious_count'])} events contained suspicious keywords "
            f"(e.g., SQL patterns, path traversal)"
        )
    if row.get("is_burst", 0) == 1:
        reasons.append(
            f"Unusual request burst detected ({int(row.get('event_count', 0))} events "
            f"in {5}-min window)"
        )
    if row.get("is_off_hours", 0) == 1:
        reasons.append(
            f"Activity occurred during off-hours (hour={int(row.get('hour', 0))}:00)"
        )
    if row.get("http_error_rate", 0) > 0.4:
        reasons.append(
            f"Elevated HTTP error rate ({row['http_error_rate']:.0%})"
        )
    if row.get("ip_failed_auth_weight", 0) > 2:
        reasons.append(
            "Source IP has a history of multiple failed authentication attempts across this log"
        )

    if not reasons:
        reasons.append(
            "Statistical deviation from baseline event patterns detected by Isolation Forest"
        )

    return "; ".join(reasons)


def run_anomaly_detection(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Train an Isolation Forest on the feature matrix and annotate each window
    with anomaly score, label, and human-readable explanation.

    Args:
        feature_df: Output of feature_engineering.engineer_features()

    Returns:
        Annotated DataFrame with additional columns:
          - anomaly_score (float, 0–1, higher = more anomalous)
          - is_anomaly (bool)
          - risk_label ('Normal' | 'Suspicious' | 'High Risk')
          - explanation (str)
    """
    df = feature_df.copy()

    # ── Validate Feature Columns ───────────────────────────────────────────────
    available = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = set(FEATURE_COLUMNS) - set(available)
    if missing:
        logger.warning("Missing feature columns (will use zeros): %s", missing)
        for col in missing:
            df[col] = 0.0

    X = df[FEATURE_COLUMNS].fillna(0).values.astype(np.float64)

    # ── Feature Scaling ────────────────────────────────────────────────────────
    # StandardScaler centers and scales each feature to unit variance.
    # Isolation Forest is sensitive to feature magnitude differences.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Model Training ─────────────────────────────────────────────────────────
    # We train on the uploaded data itself (unsupervised).
    # For small datasets (<50 windows), use lower contamination to avoid
    # excessive false positives.
    n_samples = len(X_scaled)
    contamination = min(CONTAMINATION, max(0.01, 5 / n_samples)) if n_samples >= 10 else 0.1

    logger.info(
        "Training Isolation Forest: n_samples=%d, contamination=%.3f, n_estimators=%d",
        n_samples, contamination, N_ESTIMATORS,
    )

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        max_samples=MAX_SAMPLES,
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,  # Use all available CPU cores
    )
    model.fit(X_scaled)

    # ── Scoring ────────────────────────────────────────────────────────────────
    raw_scores = model.score_samples(X_scaled)  # More negative = more anomalous
    predictions = model.predict(X_scaled)        # -1 = anomaly, 1 = normal

    df["anomaly_score"] = _normalize_scores(raw_scores)
    df["is_anomaly"] = predictions == -1

    # ── Risk Labeling ──────────────────────────────────────────────────────────
    # Three-tier labeling based on normalized anomaly score thresholds.
    def label(score: float) -> str:
        if score >= 0.65:
            return "High Risk"
        elif score >= 0.35:
            return "Suspicious"
        else:
            return "Normal"

    df["risk_label"] = df["anomaly_score"].apply(label)

    # ── Explanation Generation ─────────────────────────────────────────────────
    df["explanation"] = df.apply(_generate_explanation, axis=1)

    anomaly_count = df["is_anomaly"].sum()
    high_risk_count = (df["risk_label"] == "High Risk").sum()
    logger.info(
        "Detection complete: %d anomalous windows (%d High Risk) out of %d total",
        anomaly_count, high_risk_count, len(df),
    )

    return df
