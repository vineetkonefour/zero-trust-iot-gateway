"""
gateway/app.py
The central Flask gateway — the heart of the Zero Trust system.
"""

import os
import sys
import jwt
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import (
    GATEWAY_HOST, GATEWAY_PORT,
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_SECONDS,
    TRUST_FULL_ACCESS, TRUST_READ_ONLY
)
from database.db_init import get_connection, init_db
from anomaly.anomaly_detector import detect_anomaly

app = Flask(__name__)
CORS(app)

# ── Rate Limiter ───────────────────────────────────────────────────────────────
request_tracker = defaultdict(list)
RATE_LIMIT_WINDOW = 10
RATE_LIMIT_MAX    = 5
blocked_devices   = set()

# ── Helpers ────────────────────────────────────────────────────────────────────

def generate_token(device_id):
    payload = {
        "device_id": device_id,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=JWT_EXPIRY_SECONDS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_trust_score(device_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT score FROM trust_scores WHERE device_id = ? ORDER BY computed_at DESC LIMIT 1",
        (device_id,)
    ).fetchone()
    conn.close()
    return row["score"] if row else 100.0


def compute_and_store_trust(device_id, is_anomaly, value, device_type):
    current_score = get_trust_score(device_id)
    new_score = current_score - 15 if is_anomaly else current_score + 2
    new_score = max(0.0, min(100.0, new_score))

    if new_score >= TRUST_FULL_ACCESS:
        access_level = "full"
    elif new_score >= TRUST_READ_ONLY:
        access_level = "read_only"
    else:
        access_level = "quarantine"

    conn = get_connection()
    conn.execute(
        "INSERT INTO trust_scores (device_id, score, access_level) VALUES (?, ?, ?)",
        (device_id, new_score, access_level)
    )
    conn.commit()
    conn.close()
    return new_score, access_level


def log_access(device_id, action, reason, trust_score):
    conn = get_connection()
    conn.execute(
        "INSERT INTO access_logs (device_id, action, reason, trust_score) VALUES (?, ?, ?, ?)",
        (device_id, action, reason, trust_score)
    )
    conn.commit()
    conn.close()


def create_alert(device_id, alert_type, message, severity):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (device_id, alert_type, message, severity) VALUES (?, ?, ?, ?)",
        (device_id, alert_type, message, severity)
    )
    conn.commit()
    conn.close()


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    device_id   = data.get("device_id")
    device_type = data.get("device_type")
    location    = data.get("location")

    if not all([device_id, device_type, location]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO devices (device_id, device_type, location) VALUES (?, ?, ?)",
        (device_id, device_type, location)
    )
    conn.commit()
    conn.close()

    token = generate_token(device_id)
    print(f"[GATEWAY] Device registered: {device_id} ({device_type}) @ {location}")
    return jsonify({"token": token, "message": "Registered successfully"}), 200


@app.route("/data/ingest", methods=["POST"])
def ingest():

    # ── Rate Limiting ──────────────────────────────────────────────────────────
    incoming = request.get_json(silent=True)
    if incoming:
        did = incoming.get("device_id", "unknown")

        if did in blocked_devices:
            print(f"[GATEWAY] 🚫 BLOCKED: {did}")
            return jsonify({"error": "Device blocked due to flooding"}), 429

        now = time.time()
        request_tracker[did] = [t for t in request_tracker[did] if now - t < RATE_LIMIT_WINDOW]
        request_tracker[did].append(now)

        current_score = get_trust_score(did)
        if current_score < 40 and len(request_tracker[did]) > RATE_LIMIT_MAX:
            blocked_devices.add(did)
            create_alert(
                did,
                alert_type="rate_limit",
                message=f"{did} blocked for flooding. {len(request_tracker[did])} requests in {RATE_LIMIT_WINDOW}s",
                severity="high"
            )
            print(f"[GATEWAY] 🚫 RATE LIMIT TRIGGERED: {did} — device blocked")
            return jsonify({"error": "Rate limit exceeded — device blocked"}), 429

    # ── JWT Validation ─────────────────────────────────────────────────────────
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token   = auth_header.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    token_device_id = payload.get("device_id")

    # ── Parse Data ─────────────────────────────────────────────────────────────
    data        = incoming
    device_id   = data.get("device_id")
    value       = data.get("value")
    unit        = data.get("unit", "")
    is_anomaly  = data.get("is_anomaly", False)
    device_type = data.get("device_type", "unknown")

    if token_device_id != device_id:
        log_access(device_id, "denied", "Token/device ID mismatch", 0)
        return jsonify({"error": "Token does not match device ID"}), 403

    conn = get_connection()
    conn.execute(
        "INSERT INTO device_data (device_id, value, unit, is_anomaly) VALUES (?, ?, ?, ?)",
        (device_id, value, unit, int(is_anomaly))
    )
    conn.commit()
    conn.close()

    # ── Anomaly Detection ──────────────────────────────────────────────────────
    anomaly_result = detect_anomaly(device_id, value)
    
    # Combine simulator flag with ML detection
    is_anomaly = is_anomaly or anomaly_result["is_anomaly"]

    # ── Trust Score ────────────────────────────────────────────────────────────
    trust_score, access_level = compute_and_store_trust(device_id, is_anomaly, value, device_type)

    # Log anomaly details if detected by ML
    if anomaly_result["is_anomaly"]:
        print(f"[ANOMALY] {device_id} | method={anomaly_result['method']} | "
              f"confidence={anomaly_result['confidence']} | value={value}{unit}")

    # ── Policy Decision ────────────────────────────────────────────────────────
    if access_level == "quarantine":
        create_alert(
            device_id,
            alert_type="quarantine",
            message=f"{device_id} quarantined. Trust score: {trust_score:.1f}",
            severity="high"
        )
        log_access(device_id, "quarantined", f"Trust score: {trust_score:.1f}", trust_score)
        print(f"[GATEWAY] ⛔ QUARANTINED: {device_id} | score={trust_score:.1f}")
        return jsonify({
            "status": "quarantined",
            "trust_score": round(trust_score, 1),
            "access_level": access_level,
        }), 200

    elif access_level == "read_only":
        if is_anomaly:
            create_alert(device_id, "anomaly",
                         f"Anomalous reading from {device_id}: {value}{unit}", "medium")
        log_access(device_id, "allowed", f"Read-only. Trust: {trust_score:.1f}", trust_score)
        print(f"[GATEWAY] ⚠ READ-ONLY: {device_id} | score={trust_score:.1f} | value={value}{unit}")
        return jsonify({
            "status": "read_only",
            "trust_score": round(trust_score, 1),
            "access_level": access_level,
        }), 200

    else:
        if is_anomaly:
            create_alert(device_id, "anomaly",
                         f"Anomalous reading from {device_id}: {value}{unit}", "low")
        log_access(device_id, "allowed", f"Full access. Trust: {trust_score:.1f}", trust_score)
        print(f"[GATEWAY] ✓ FULL ACCESS: {device_id} | score={trust_score:.1f} | value={value}{unit}")
        return jsonify({
            "status": "allowed",
            "trust_score": round(trust_score, 1),
            "access_level": access_level,
        }), 200


@app.route("/devices", methods=["GET"])
def get_devices():
    conn = get_connection()
    devices = conn.execute("SELECT * FROM devices").fetchall()
    result = []
    for d in devices:
        latest = conn.execute(
            "SELECT score, access_level, computed_at FROM trust_scores WHERE device_id = ? ORDER BY computed_at DESC LIMIT 1",
            (d["device_id"],)
        ).fetchone()
        result.append({
            "device_id":    d["device_id"],
            "device_type":  d["device_type"],
            "location":     d["location"],
            "trust_score":  round(latest["score"], 1) if latest else 100.0,
            "access_level": latest["access_level"] if latest else "full",
            "last_seen":    latest["computed_at"] if latest else None,
        })
    conn.close()
    return jsonify(result), 200


@app.route("/alerts", methods=["GET"])
def get_alerts():
    conn = get_connection()
    alerts = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(a) for a in alerts]), 200


@app.route("/logs", methods=["GET"])
def get_logs():
    conn = get_connection()
    logs = conn.execute("SELECT * FROM access_logs ORDER BY logged_at DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs]), 200


@app.route("/trust/<device_id>", methods=["GET"])
def get_trust_history(device_id):
    conn = get_connection()
    history = conn.execute(
        "SELECT score, access_level, computed_at FROM trust_scores WHERE device_id = ? ORDER BY computed_at DESC LIMIT 50",
        (device_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(h) for h in history]), 200


@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "running", "message": "Zero Trust IoT Gateway is active"}), 200


# ── Start ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Zero Trust IoT Security Gateway")
    print(f"  Running on http://{GATEWAY_HOST}:{GATEWAY_PORT}")
    print("=" * 60)
    init_db()
    app.run(host=GATEWAY_HOST, port=GATEWAY_PORT, debug=True)