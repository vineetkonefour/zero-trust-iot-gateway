"""
anomaly/anomaly_detector.py

Two-layer anomaly detection:
  Layer 1 — Z-Score: fast statistical check on each reading
  Layer 2 — Isolation Forest: ML-based detection trained on device history

How it works:
  - Every incoming reading is first checked by Z-Score (instant)
  - After 50+ readings, Isolation Forest kicks in for deeper analysis
  - Both layers feed a combined anomaly confidence score
  - This score influences the trust engine
"""

import os
import sys
import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db_init import get_connection

# ── Config ─────────────────────────────────────────────────────────────────────
ZSCORE_THRESHOLD        = 2.5   # how many std deviations = anomaly
MIN_SAMPLES_FOR_ML      = 50    # minimum readings before Isolation Forest activates
ISOLATION_CONTAMINATION = 0.1   # expected 10% anomaly rate in training data

# In-memory model cache: device_id → trained IsolationForest model
_models = {}


# ── Layer 1: Z-Score Detection ─────────────────────────────────────────────────

def zscore_check(device_id: str, new_value: float) -> tuple:
    """
    Compare new reading against historical mean and std deviation.
    Returns (is_anomaly: bool, confidence: float, reason: str)
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT value FROM device_data WHERE device_id = ? ORDER BY received_at DESC LIMIT 100",
        (device_id,)
    ).fetchall()
    conn.close()

    if len(rows) < 10:
        # Not enough history yet — cannot judge
        return False, 0.0, "insufficient_history"

    values = np.array([r["value"] for r in rows], dtype=float)
    mean   = np.mean(values)
    std    = np.std(values)

    if std == 0:
        # All readings identical — new value is anomaly if different
        is_anomaly = new_value != mean
        return is_anomaly, 1.0 if is_anomaly else 0.0, "zero_variance"

    z_score = abs((new_value - mean) / std)
    is_anomaly = z_score > ZSCORE_THRESHOLD
    confidence = min(1.0, z_score / (ZSCORE_THRESHOLD * 2))

    reason = f"z_score={z_score:.2f} (mean={mean:.1f}, std={std:.1f})"
    return is_anomaly, confidence, reason


# ── Layer 2: Isolation Forest Detection ───────────────────────────────────────

def isolation_forest_check(device_id: str, new_value: float) -> tuple:
    """
    Use Isolation Forest ML model to detect anomalies.
    Model is trained on the device's historical data.
    Returns (is_anomaly: bool, confidence: float)
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT value FROM device_data WHERE device_id = ? ORDER BY received_at DESC LIMIT 200",
        (device_id,)
    ).fetchall()
    conn.close()

    if len(rows) < MIN_SAMPLES_FOR_ML:
        return False, 0.0

    values = np.array([r["value"] for r in rows], dtype=float).reshape(-1, 1)

    # Train or retrain model every 50 new samples
    if device_id not in _models or len(rows) % 50 == 0:
        model = IsolationForest(
            contamination=ISOLATION_CONTAMINATION,
            random_state=42,
            n_estimators=100
        )
        model.fit(values)
        _models[device_id] = model

    model = _models[device_id]

    # Predict: -1 = anomaly, 1 = normal
    prediction = model.predict([[new_value]])[0]
    score      = model.score_samples([[new_value]])[0]

    # Convert score to confidence (more negative = more anomalous)
    confidence = max(0.0, min(1.0, abs(score) / 0.5))
    is_anomaly = prediction == -1

    return is_anomaly, confidence


# ── Combined Detection ─────────────────────────────────────────────────────────

def detect_anomaly(device_id: str, new_value: float) -> dict:
    """
    Run both detection layers and combine results.

    Returns a result dict:
    {
        "is_anomaly"  : bool,
        "confidence"  : float (0.0 to 1.0),
        "method"      : str,
        "reason"      : str,
        "trust_penalty": float
    }
    """
    # Layer 1 — Z-Score
    z_anomaly, z_confidence, z_reason = zscore_check(device_id, new_value)

    # Layer 2 — Isolation Forest
    if_anomaly, if_confidence = isolation_forest_check(device_id, new_value)

    # Combine: anomaly if either layer flags it
    # Weight: Z-Score 40%, Isolation Forest 60%
    combined_confidence = (z_confidence * 0.4) + (if_confidence * 0.6)
    is_anomaly          = z_anomaly or if_anomaly

    # Determine which method caught it
    if z_anomaly and if_anomaly:
        method = "both_layers"
    elif z_anomaly:
        method = "zscore"
    elif if_anomaly:
        method = "isolation_forest"
    else:
        method = "none"

    # Trust penalty scales with confidence
    trust_penalty = round(combined_confidence * 20, 1) if is_anomaly else 0.0

    return {
        "is_anomaly":    is_anomaly,
        "confidence":    round(combined_confidence, 3),
        "method":        method,
        "reason":        z_reason,
        "trust_penalty": trust_penalty,
    }


# ── Standalone Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Testing anomaly detector...")
    print("Run the simulator first to collect some data, then test here.")

    conn = get_connection()
    devices = conn.execute("SELECT DISTINCT device_id FROM device_data").fetchall()
    conn.close()

    if not devices:
        print("No device data found. Start the simulator first.")
    else:
        for d in devices:
            did = d["device_id"]
            result = detect_anomaly(did, 999.0)  # obviously anomalous value
            print(f"\n{did}:")
            print(f"  Anomaly    : {result['is_anomaly']}")
            print(f"  Confidence : {result['confidence']}")
            print(f"  Method     : {result['method']}")
            print(f"  Penalty    : {result['trust_penalty']}")