"""
dashboard/dashboard.py

Live Streamlit dashboard for the Zero Trust IoT Security Gateway.
Auto-refreshes every 3 seconds to show real-time data.

Run with: streamlit run dashboard/dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import DB_PATH

# ── Page Config ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Zero Trust IoT Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Styling ────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: #1e2130;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        border: 1px solid #2e3250;
    }
    .full-access    { border-left: 4px solid #00cc66; }
    .read-only      { border-left: 4px solid #ffaa00; }
    .quarantine     { border-left: 4px solid #ff4444; }
    .alert-high     { color: #ff4444; font-weight: bold; }
    .alert-medium   { color: #ffaa00; font-weight: bold; }
    .alert-low      { color: #00cc66; }
</style>
""", unsafe_allow_html=True)

# ── Database Helpers ───────────────────────────────────────────────────────────

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def get_devices():
    conn = get_conn()
    devices = pd.read_sql("""
        SELECT d.device_id, d.device_type, d.location,
               t.score, t.access_level, t.computed_at
        FROM devices d
        LEFT JOIN (
            SELECT device_id, score, access_level, computed_at,
                   ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY computed_at DESC) as rn
            FROM trust_scores
        ) t ON d.device_id = t.device_id AND t.rn = 1
    """, conn)
    conn.close()
    return devices


def get_alerts(limit=20):
    conn = get_conn()
    alerts = pd.read_sql(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
        conn, params=(limit,)
    )
    conn.close()
    return alerts


def get_trust_history(device_id):
    conn = get_conn()
    history = pd.read_sql(
        "SELECT score, access_level, computed_at FROM trust_scores WHERE device_id = ? ORDER BY computed_at ASC",
        conn, params=(device_id,)
    )
    conn.close()
    return history


def get_summary_stats():
    conn = get_conn()
    total_devices  = pd.read_sql("SELECT COUNT(*) as c FROM devices", conn).iloc[0]["c"]
    total_alerts   = pd.read_sql("SELECT COUNT(*) as c FROM alerts", conn).iloc[0]["c"]
    total_readings = pd.read_sql("SELECT COUNT(*) as c FROM device_data", conn).iloc[0]["c"]
    quarantined    = pd.read_sql("""
        SELECT COUNT(DISTINCT device_id) as c FROM trust_scores
        WHERE access_level = 'quarantine'
        AND computed_at = (SELECT MAX(computed_at) FROM trust_scores t2 WHERE t2.device_id = trust_scores.device_id)
    """, conn).iloc[0]["c"]
    conn.close()
    return int(total_devices), int(total_alerts), int(total_readings), int(quarantined)


def get_access_log(limit=50):
    conn = get_conn()
    logs = pd.read_sql(
        "SELECT * FROM access_logs ORDER BY logged_at DESC LIMIT ?",
        conn, params=(limit,)
    )
    conn.close()
    return logs


# ── Dashboard Layout ───────────────────────────────────────────────────────────

def render_dashboard():

    # Header
    st.markdown("## 🔒 Zero Trust IoT Security Gateway")
    st.markdown("---")

    # ── Summary Stats Row ──────────────────────────────────────────────────────
    total_devices, total_alerts, total_readings, quarantined = get_summary_stats()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Devices",    total_devices)
    with col2:
        st.metric("Total Readings",   total_readings)
    with col3:
        st.metric("Alerts Generated", total_alerts)
    with col4:
        st.metric("Quarantined Now",  quarantined,
                  delta=f"{quarantined} at risk" if quarantined > 0 else "All clear",
                  delta_color="inverse")

    st.markdown("---")

    # ── Device Status Grid ─────────────────────────────────────────────────────
    st.markdown("### 📡 Device Status")

    devices = get_devices()

    if devices.empty:
        st.info("No devices registered yet. Start the simulator to see devices.")
        return

    # Fill missing scores for new devices
    devices["score"]        = devices["score"].fillna(100.0)
    devices["access_level"] = devices["access_level"].fillna("full")

    cols = st.columns(4)
    for i, (_, device) in enumerate(devices.iterrows()):
        score        = float(device["score"])
        access_level = device["access_level"]
        device_id    = device["device_id"]
        device_type  = device["device_type"]
        location     = device["location"]

        # Color based on access level
        if access_level == "full":
            color     = "#00cc66"
            icon      = "✅"
            css_class = "full-access"
        elif access_level == "read_only":
            color     = "#ffaa00"
            icon      = "⚠️"
            css_class = "read-only"
        else:
            color     = "#ff4444"
            icon      = "⛔"
            css_class = "quarantine"

        with cols[i % 4]:
            st.markdown(f"""
            <div class="metric-card {css_class}">
                <h4 style="color:{color}">{icon} {device_id}</h4>
                <p style="color:#aaa;font-size:12px">{device_type}<br>{location}</p>
                <h2 style="color:{color}">{score:.1f}</h2>
                <p style="color:#aaa;font-size:12px">Trust Score</p>
                <span style="color:{color};font-size:11px;text-transform:uppercase">
                    {access_level.replace("_", " ")}
                </span>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("")

    st.markdown("---")

    # ── Trust Score Chart ──────────────────────────────────────────────────────
    st.markdown("### 📈 Trust Score History")

    selected_device = st.selectbox(
        "Select device to inspect:",
        options=devices["device_id"].tolist()
    )

    history = get_trust_history(selected_device)

    if not history.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=history["computed_at"],
            y=history["score"],
            mode="lines+markers",
            name="Trust Score",
            line=dict(color="#00aaff", width=2),
            marker=dict(size=4)
        ))
        # Threshold lines
        fig.add_hline(y=70, line_dash="dash", line_color="#00cc66",
                      annotation_text="Full Access (70)", annotation_position="right")
        fig.add_hline(y=40, line_dash="dash", line_color="#ffaa00",
                      annotation_text="Read Only (40)", annotation_position="right")

        fig.update_layout(
            paper_bgcolor="#1e2130",
            plot_bgcolor="#1e2130",
            font=dict(color="#ffffff"),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#2e3250", range=[0, 105]),
            margin=dict(l=20, r=20, t=20, b=20),
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No trust score history yet for this device.")

    st.markdown("---")

    # ── Two Column Layout: Alerts + Access Log ─────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("### 🚨 Recent Alerts")
        alerts = get_alerts(20)
        if alerts.empty:
            st.success("No alerts generated yet.")
        else:
            for _, alert in alerts.iterrows():
                severity = alert.get("severity", "low")
                if severity == "high":
                    icon = "🔴"
                elif severity == "medium":
                    icon = "🟡"
                else:
                    icon = "🟢"
                st.markdown(
                    f"{icon} **{alert['device_id']}** — {alert['message']}  \n"
                    f"<span style='color:#666;font-size:11px'>{alert['created_at']}</span>",
                    unsafe_allow_html=True
                )

    with col_right:
        st.markdown("### 📋 Access Log")
        logs = get_access_log(20)
        if logs.empty:
            st.info("No access logs yet.")
        else:
            for _, log in logs.iterrows():
                action = log.get("action", "")
                if action == "allowed":
                    icon = "✅"
                elif action == "quarantined":
                    icon = "⛔"
                else:
                    icon = "❌"
                st.markdown(
                    f"{icon} **{log['device_id']}** — {log['action']} "
                    f"(score: {log['trust_score']:.1f})  \n"
                    f"<span style='color:#666;font-size:11px'>{log['logged_at']}</span>",
                    unsafe_allow_html=True
                )

    st.markdown("---")

    # ── Access Level Distribution Chart ───────────────────────────────────────
    st.markdown("### 🥧 Access Level Distribution")

    access_counts = devices["access_level"].value_counts().reset_index()
    access_counts.columns = ["access_level", "count"]

    color_map = {
        "full":       "#00cc66",
        "read_only":  "#ffaa00",
        "quarantine": "#ff4444"
    }

    fig2 = px.pie(
        access_counts,
        names="access_level",
        values="count",
        color="access_level",
        color_discrete_map=color_map,
        hole=0.4
    )
    fig2.update_layout(
        paper_bgcolor="#1e2130",
        font=dict(color="#ffffff"),
        margin=dict(l=20, r=20, t=20, b=20),
        height=300
    )
    st.plotly_chart(fig2, use_container_width=True)

    # Auto refresh
    st.markdown("---")
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')} — Refresh the page to update")


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == "__main__" or True:
    render_dashboard()