"""
SQLite storage layer for the simulated VIT cloud security system.

We use SQLite (zero setup, single file) for the student-project prototype.
The schema is deliberately close to what you'd use on PostgreSQL later -
swapping the driver is a later-phase upgrade, not a redesign.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "vit_cloud_security.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            department TEXT,
            status TEXT DEFAULT 'ACTIVE'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id TEXT,
            event_type TEXT,     -- LOGIN_SUCCESS / LOGIN_FAILED / FILE_VIEW / FILE_DOWNLOAD / API_REQUEST ...
            detail TEXT          -- JSON blob with extra fields
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            user_id TEXT,
            timestamp TEXT,
            threat_score INTEGER,
            classification TEXT,
            detected_by TEXT,     -- JSON list of agent names + their scores
            evidence TEXT,        -- JSON list of evidence strings
            actions TEXT,         -- JSON list of response actions
            status TEXT           -- MONITORED / ALERTED / BLOCKED
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            actor TEXT,           -- which agent / system component
            action TEXT,
            user_id TEXT
        )
    """)

    conn.commit()
    conn.close()


def reset_db():
    """Wipes runtime tables (events / incidents / audit_log) but keeps users."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM events")
    cur.execute("DELETE FROM incidents")
    cur.execute("DELETE FROM audit_log")
    conn.commit()
    conn.close()


def seed_users(users: list):
    conn = get_connection()
    cur = conn.cursor()
    for u in users:
        cur.execute("""
            INSERT OR REPLACE INTO users (user_id, name, role, department, status)
            VALUES (?, ?, ?, ?, COALESCE((SELECT status FROM users WHERE user_id = ?), 'ACTIVE'))
        """, (u["user_id"], u["name"], u["role"], u["department"], u["user_id"]))
    conn.commit()
    conn.close()


def insert_event(timestamp, user_id, event_type, detail: dict):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events (timestamp, user_id, event_type, detail)
        VALUES (?, ?, ?, ?)
    """, (timestamp, user_id, event_type, json.dumps(detail)))
    conn.commit()
    conn.close()


def insert_incident(incident: dict):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO incidents
        (incident_id, user_id, timestamp, threat_score, classification, detected_by, evidence, actions, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident["incident_id"], incident["user_id"], incident["timestamp"],
        incident["threat_score"], incident["classification"],
        json.dumps(incident["detected_by"]), json.dumps(incident["evidence"]),
        json.dumps(incident["actions"]), incident["status"],
    ))
    conn.commit()
    conn.close()


def insert_audit(actor, action, user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log (timestamp, actor, action, user_id)
        VALUES (?, ?, ?, ?)
    """, (datetime.utcnow().isoformat() + "Z", actor, action, user_id))
    conn.commit()
    conn.close()


def set_user_status(user_id, status):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = ? WHERE user_id = ?", (status, user_id))
    conn.commit()
    conn.close()


def fetch_all(query, params=()):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
