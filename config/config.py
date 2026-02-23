# ─────────────────────────────────────────────
#  Zero Trust IoT Security Gateway — Config
# ─────────────────────────────────────────────

# Gateway
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 5000

# JWT
JWT_SECRET = "zt_iot_secret_key_2025"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600

# Database
DB_PATH = "database/zt_iot.db"

# Trust Score Thresholds
TRUST_FULL_ACCESS   = 70   # score >= 70 → full access
TRUST_READ_ONLY     = 40   # score 40–69 → read only
TRUST_QUARANTINE    = 40   # score < 40  → quarantined

# Simulation
SIMULATION_INTERVAL = 3    # seconds between device data sends
ANOMALY_INJECTION_PROBABILITY = 0.08  # 8% chance a device acts anomalously each cycle

# Device Types and their normal data ranges
DEVICE_PROFILES = {
    "temperature_sensor": {
        "unit": "°C",
        "normal_range": (18, 35),
        "anomaly_range": (80, 150),
        "request_rate_normal": 1,
    },
    "smart_lock": {
        "unit": "status",
        "normal_range": (0, 1),
        "anomaly_range": (0, 1),
        "request_rate_normal": 1,
    },
    "humidity_sensor": {
        "unit": "%RH",
        "normal_range": (30, 70),
        "anomaly_range": (95, 100),
        "request_rate_normal": 1,
    },
    "motion_detector": {
        "unit": "events",
        "normal_range": (0, 3),
        "anomaly_range": (20, 50),
        "request_rate_normal": 1,
    },
    "smart_camera": {
        "unit": "fps",
        "normal_range": (24, 30),
        "anomaly_range": (0, 1),
        "request_rate_normal": 1,
    },
}