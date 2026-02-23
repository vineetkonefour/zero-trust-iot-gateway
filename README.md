# Zero Trust IoT Security Gateway
### 5th Semester Engineering Project | Network Defense + IoT

---

## What This Project Does

Simulates a Zero Trust Architecture applied to an IoT network.
IoT devices must continuously **authenticate and earn trust** — no device is trusted by default.
The system computes a live **trust score** for each device and enforces **access control policies** accordingly.
An ML-based anomaly detector independently flags suspicious behavior without relying on device self-reporting.

---

## Architecture
```
[IoT Devices]  →  [Gateway + Auth Layer]  →  [Trust Score Engine]
                          ↓                          ↓
                  [Policy Engine]           [Anomaly Detector]
                  [Rate Limiter]            [Z-Score + Isolation Forest]
                          ↓
                    [SQLite DB]  →  [Streamlit Dashboard]
```

---

## Project Structure
```
zt_iot/
│
├── config/
│   └── config.py              ← All settings (thresholds, ports, device profiles)
│
├── database/
│   └── db_init.py             ← SQLite schema + connection helper
│
├── simulator/
│   └── device_simulator.py    ← 8 simulated IoT devices (threaded)
│
├── gateway/
│   └── app.py                 ← Flask gateway (auth, ingestion, policy, rate limiting)
│
├── anomaly/
│   └── anomaly_detector.py    ← Z-Score + Isolation Forest anomaly detection
│
├── dashboard/
│   └── dashboard.py           ← Streamlit live dashboard
│
└── requirements.txt
```

---

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/vineetkonefour/zero-trust-iot-gateway.git
cd zero-trust-iot-gateway
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize the database
```bash
python database/db_init.py
```

### 5. Start the gateway (Terminal 1)
```bash
python gateway/app.py
```

### 6. Start the device simulator (Terminal 2)
```bash
python simulator/device_simulator.py
```

### 7. Launch the dashboard (Terminal 3)
```bash
streamlit run dashboard/dashboard.py
```

---

## Key Concepts Demonstrated

| Concept | Implementation |
|---|---|
| Zero Trust "never trust, always verify" | JWT validated on every single request |
| Continuous authorization | Trust score recomputed every data cycle |
| Least privilege access | 3-tier access (full / read-only / quarantine) |
| ML-based anomaly detection | Z-Score + Isolation Forest on live data streams |
| DDoS mitigation | Rate limiter blocks flooding quarantined devices |
| Policy engine | Rule-based access control (ABAC) |
| Full audit trail | Every decision logged with timestamp |

---

## Trust Score Formula
```
Starting score: 100

Normal reading   → +2 points  (reward consistent good behavior)
Anomaly detected → -15 points (penalize bad behavior)

Clamped between 0 and 100
```

| Score | Access Level |
|---|---|
| ≥ 70 | ✅ Full Access |
| 40–69 | ⚠️ Read Only |
| < 40 | ⛔ Quarantined |

---

## Anomaly Detection — Two Layers

**Layer 1 — Z-Score (Statistical)**
- Activates after 10 readings per device
- Flags values more than 2.5 standard deviations from the device's historical mean
- Fast, lightweight, works immediately

**Layer 2 — Isolation Forest (Machine Learning)**
- Activates after 50 readings per device
- Trains on last 200 readings, retrains every 50 new samples
- Detects subtle behavioral anomalies that Z-Score might miss
- Combined confidence score: Z-Score 40% + Isolation Forest 60%

---

## References
- NIST SP 800-207 — Zero Trust Architecture
- OWASP IoT Security Top 10
- RFC 7519 — JSON Web Tokens (JWT)
- Scikit-learn: Isolation Forest Documentation

