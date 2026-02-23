"""
simulator/device_simulator.py

Simulates multiple IoT devices as threads.
Each device:
  - Has a unique ID, type, and location
  - Sends periodic data payloads to the gateway
  - Occasionally injects anomalous behavior (configurable probability)
  - Handles JWT authentication automatically
"""

import threading
import time
import random
import requests
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import (
    GATEWAY_HOST, GATEWAY_PORT,
    SIMULATION_INTERVAL,
    ANOMALY_INJECTION_PROBABILITY,
    DEVICE_PROFILES
)

GATEWAY_URL = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}"

# ── Device Definitions ─────────────────────────────────────────────────────────
SIMULATED_DEVICES = [
    {"device_id": "DEV_TEMP_01",   "device_type": "temperature_sensor", "location": "Server Room A"},
    {"device_id": "DEV_TEMP_02",   "device_type": "temperature_sensor", "location": "Server Room B"},
    {"device_id": "DEV_LOCK_01",   "device_type": "smart_lock",         "location": "Main Entrance"},
    {"device_id": "DEV_LOCK_02",   "device_type": "smart_lock",         "location": "Back Door"},
    {"device_id": "DEV_HUM_01",    "device_type": "humidity_sensor",    "location": "Data Center"},
    {"device_id": "DEV_MOTION_01", "device_type": "motion_detector",    "location": "Corridor 1"},
    {"device_id": "DEV_MOTION_02", "device_type": "motion_detector",    "location": "Parking Lot"},
    {"device_id": "DEV_CAM_01",    "device_type": "smart_camera",       "location": "Main Lobby"},
]


class IoTDevice(threading.Thread):
    """
    Simulates a single IoT device.
    Runs as a background thread, sending data to the gateway every SIMULATION_INTERVAL seconds.
    """

    def __init__(self, device_id, device_type, location, stop_event):
        super().__init__(name=device_id, daemon=True)
        self.device_id   = device_id
        self.device_type = device_type
        self.location    = location
        self.stop_event  = stop_event
        self.token       = None
        self.profile     = DEVICE_PROFILES[device_type]

        self.consecutive_anomalies = 0
        self.total_sends           = 0
        self.failed_auths          = 0

    # ── Authentication ─────────────────────────────────────────────────────────

    def register_and_authenticate(self):
        """Register device with gateway and obtain a JWT token."""
        try:
            payload = {
                "device_id":   self.device_id,
                "device_type": self.device_type,
                "location":    self.location,
            }
            resp = requests.post(f"{GATEWAY_URL}/auth/register", json=payload, timeout=5)
            if resp.status_code == 200:
                self.token = resp.json().get("token")
                self._log("Authenticated ✓")
                return True
            else:
                self._log(f"Auth failed: {resp.status_code}")
                self.failed_auths += 1
                return False
        except requests.exceptions.ConnectionError:
            self._log("Gateway not reachable — will retry.")
            return False

    # ── Data Generation ────────────────────────────────────────────────────────

    def generate_data(self):
        """Generate a sensor reading — normal or anomalous."""
        inject_anomaly = random.random() < ANOMALY_INJECTION_PROBABILITY

        if inject_anomaly:
            low, high = self.profile["anomaly_range"]
            self.consecutive_anomalies += 1
        else:
            low, high = self.profile["normal_range"]
            self.consecutive_anomalies = 0

        if self.device_type == "smart_lock":
            value = random.choice([0, 1])
        else:
            value = round(random.uniform(low, high), 2)

        return {
            "device_id":   self.device_id,
            "device_type": self.device_type,
            "value":       value,
            "unit":        self.profile["unit"],
            "is_anomaly":  inject_anomaly,
            "timestamp":   datetime.utcnow().isoformat(),
        }

    # ── Sending Data ───────────────────────────────────────────────────────────

    def send_data(self, data):
        """POST sensor data to the gateway with JWT in header."""
        if not self.token:
            return False
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            resp = requests.post(
                f"{GATEWAY_URL}/data/ingest",
                json=data,
                headers=headers,
                timeout=5
            )
            if resp.status_code == 200:
                result = resp.json()
                status = result.get("access_level", "unknown")
                score  = result.get("trust_score", "?")
                self._log(f"Sent value={data['value']}{data['unit']} | "
                          f"trust={score} | access={status}"
                          + (" ⚠ ANOMALY" if data["is_anomaly"] else ""))
                return True
            elif resp.status_code == 401:
                self._log("Token expired — re-authenticating.")
                self.token = None
                return False
            elif resp.status_code == 403:
                self._log("ACCESS DENIED — quarantined by policy engine.")
                return False
            else:
                self._log(f"Unexpected response: {resp.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self._log("Gateway not reachable.")
            return False

    # ── Main Loop ──────────────────────────────────────────────────────────────

    def run(self):
        """Device lifecycle: authenticate → loop sending data."""
        self._log("Starting up...")

        while not self.stop_event.is_set():
            if self.register_and_authenticate():
                break
            time.sleep(5)

        while not self.stop_event.is_set():
            self.total_sends += 1

            if not self.token:
                self.register_and_authenticate()

            data = self.generate_data()
            self.send_data(data)

            jitter = random.uniform(-0.5, 0.5)
            time.sleep(max(1, SIMULATION_INTERVAL + jitter))

    # ── Utility ────────────────────────────────────────────────────────────────

    def _log(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{self.device_id}] {message}")


# ── Simulation Runner ──────────────────────────────────────────────────────────

def run_simulation(device_list=None):
    """Start all device threads."""
    if device_list is None:
        device_list = SIMULATED_DEVICES

    stop_event = threading.Event()
    threads = []

    print(f"\n[SIMULATOR] Starting {len(device_list)} IoT devices...\n")

    for dev in device_list:
        device = IoTDevice(
            device_id=dev["device_id"],
            device_type=dev["device_type"],
            location=dev["location"],
            stop_event=stop_event,
        )
        device.start()
        threads.append(device)
        time.sleep(0.2)

    return threads, stop_event


if __name__ == "__main__":
    print("=" * 60)
    print("  Zero Trust IoT — Device Simulator")
    print("  Make sure the gateway is running first.")
    print("=" * 60)

    threads, stop_event = run_simulation()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SIMULATOR] Stopping all devices...")
        stop_event.set()
        for t in threads:
            t.join(timeout=3)
        print("[SIMULATOR] All devices stopped.")