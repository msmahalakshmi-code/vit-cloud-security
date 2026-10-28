"""
VIT CLOUD SECURITY CENTER - backend
-------------------------------------
FastAPI app that:
  - Loads/generates the synthetic dataset and seeds SQLite on startup
  - Runs a background thread emitting light "normal" traffic continuously
    so the dashboard feels alive
  - Exposes REST endpoints for the dashboard (summary, users, incidents,
    agent status, audit log) and a "trigger scenario" endpoint that plays
    one of the 5 project-spec attack scenarios through the real agents

Run from the project root:
    uvicorn backend.main:app --reload --port 8000

Dashboard:
    http://127.0.0.1:8000/
API docs (auto-generated):
    http://127.0.0.1:8000/docs
"""

import os
import csv
import random
import threading
import time
import subprocess
import sys

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from backend import database as db
from backend.engine import engine
from simulator.realtime_simulator import normal_event, SCENARIOS

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
DATASET_DIR = os.path.join(ROOT, "dataset")
FRONTEND_DIR = os.path.join(ROOT, "frontend")

app = FastAPI(title="VIT Cloud Security Center")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_users_cache = []
_background_thread_started = False


# ----------------------------------------------------------------------
# STARTUP: ensure dataset exists, seed DB, warm up engine's "known device" cache
# ----------------------------------------------------------------------
@app.on_event("startup")
def startup():
    global _users_cache, _background_thread_started

    users_csv = os.path.join(DATASET_DIR, "users.csv")
    if not os.path.exists(users_csv):
        print("[startup] No dataset found - generating synthetic VIT dataset...")
        subprocess.run([sys.executable, os.path.join(ROOT, "simulator", "generate_data.py")], check=True)

    db.init_db()
    db.reset_db()

    with open(users_csv, newline="") as f:
        _users_cache = list(csv.DictReader(f))

    db.seed_users([
        {"user_id": u["user_id"], "name": u["name"], "role": u["role"], "department": u["department"]}
        for u in _users_cache
    ])

    # warm the engine's known-device/known-ip cache with each user's "home" device,
    # so their first normal login of the session isn't flagged as "new device"
    for u in _users_cache:
        engine._known_devices[u["user_id"]].add(u["home_device"])
        engine._known_ips[u["user_id"]].add(u["home_ip"])

    if not _background_thread_started:
        t = threading.Thread(target=_background_normal_traffic, daemon=True)
        t.start()
        _background_thread_started = True

    print(f"[startup] Ready. {len(_users_cache)} simulated users loaded.")


def _background_normal_traffic():
    """Continuously trickles ordinary events for random users so the
    dashboard has live baseline activity even with no attack triggered."""
    while True:
        time.sleep(random.uniform(1.5, 3.5))
        if not _users_cache:
            continue
        user = random.choice(_users_cache)
        event_type, detail = normal_event(user)
        try:
            engine.process_event(user["user_id"], event_type, detail)
        except Exception as e:
            print(f"[background_traffic] error: {e}")


# ----------------------------------------------------------------------
# DASHBOARD SUMMARY
# ----------------------------------------------------------------------
@app.get("/api/dashboard/summary")
def dashboard_summary():
    users = db.fetch_all("SELECT * FROM users")
    events = db.fetch_all("SELECT COUNT(*) as c FROM events")
    incidents = db.fetch_all("SELECT * FROM incidents ORDER BY timestamp DESC")

    critical = sum(1 for i in incidents if i["classification"] == "CRITICAL")
    high = sum(1 for i in incidents if i["classification"] == "HIGH")
    blocked_users = sum(1 for u in users if u["status"] == "BLOCKED")
    flagged_users = sum(1 for u in users if u["status"] == "FLAGGED")

    by_class = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for i in incidents:
        by_class[i["classification"]] = by_class.get(i["classification"], 0) + 1

    return {
        "active_users": len(users),
        "blocked_users": blocked_users,
        "flagged_users": flagged_users,
        "files_monitored": len(_files_index()),
        "security_events": events[0]["c"] if events else 0,
        "total_incidents": len(incidents),
        "critical_threats": critical,
        "high_threats": high,
        "threat_distribution": by_class,
        "recent_incidents": incidents[:5],
        "agent_status": engine.agent_status,
    }


def _files_index():
    path = os.path.join(DATASET_DIR, "file_access_logs.csv")
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


# ----------------------------------------------------------------------
# USERS
# ----------------------------------------------------------------------
@app.get("/api/users")
def list_users():
    return db.fetch_all("SELECT * FROM users ORDER BY role, user_id")


@app.get("/api/users/{user_id}")
def get_user(user_id: str):
    rows = db.fetch_all("SELECT * FROM users WHERE user_id = ?", (user_id,))
    if not rows:
        raise HTTPException(404, "User not found")
    events = db.fetch_all(
        "SELECT * FROM events WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user_id,))
    incidents = db.fetch_all(
        "SELECT * FROM incidents WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    return {"user": rows[0], "recent_events": events, "incidents": incidents}


@app.post("/api/users/{user_id}/unblock")
def unblock_user(user_id: str):
    db.set_user_status(user_id, "ACTIVE")
    db.insert_audit("Administrator (manual)", "Account manually restored", user_id)
    return {"status": "ok"}


# ----------------------------------------------------------------------
# INCIDENTS
# ----------------------------------------------------------------------
@app.get("/api/incidents")
def list_incidents():
    return db.fetch_all("SELECT * FROM incidents ORDER BY timestamp DESC")


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    rows = db.fetch_all("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    if not rows:
        raise HTTPException(404, "Incident not found")
    return rows[0]


# ----------------------------------------------------------------------
# AUDIT LOG
# ----------------------------------------------------------------------
@app.get("/api/audit-log")
def audit_log():
    return db.fetch_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")


# ----------------------------------------------------------------------
# AGENTS
# ----------------------------------------------------------------------
@app.get("/api/agents/status")
def agents_status():
    return engine.agent_status


# ----------------------------------------------------------------------
# SIMULATION CONTROL
# ----------------------------------------------------------------------
@app.get("/api/scenarios")
def list_scenarios():
    return {
        "compromised_account": "Scenario 1 - Compromised Student Account (failed logins -> new device -> mass access)",
        "unauthorized_academic_access": "Scenario 2 - Unauthorized Academic File Access (exam paper)",
        "excessive_download": "Scenario 3 - Excessive Data Download",
        "bruteforce_login": "Scenario 4 - Brute-force-like Login Pattern",
        "api_burst": "Scenario 5 - API Request Burst",
    }


@app.post("/api/simulate/{scenario_name}")
def simulate(scenario_name: str, background_tasks: BackgroundTasks, user_id: str = None):
    if scenario_name not in SCENARIOS:
        raise HTTPException(404, f"Unknown scenario. Choose from: {list(SCENARIOS.keys())}")

    if user_id:
        matches = [u for u in _users_cache if u["user_id"] == user_id]
        if not matches:
            raise HTTPException(404, "Unknown user_id")
        user = matches[0]
    else:
        student_users = [u for u in _users_cache if u["role"] == "Student"]
        user = random.choice(student_users or _users_cache)

    background_tasks.add_task(_run_scenario, scenario_name, user)
    return {"status": "scenario started", "scenario": scenario_name, "user_id": user["user_id"]}


def _run_scenario(scenario_name, user):
    events = SCENARIOS[scenario_name](user)
    db.insert_audit("Real-Time Event Simulator",
                     f"Started scenario '{scenario_name}' with {len(events)} events", user["user_id"])
    for event_type, detail in events:
        engine.process_event(user["user_id"], event_type, detail)
        time.sleep(0.02)   # tiny delay so it streams rather than freezing the loop


@app.post("/api/reset")
def reset():
    db.reset_db()
    for u in _users_cache:
        db.set_user_status(u["user_id"], "ACTIVE")
    engine._history.clear()
    engine._last_incident_at.clear()
    return {"status": "reset complete"}




# ----------------------------------------------------------------------
# SECURITY INTELLIGENCE: local simulated controls and investigation APIs
# ----------------------------------------------------------------------
import json as _json
from datetime import datetime as _datetime, timezone as _timezone
from pydantic import BaseModel as _BaseModel
from typing import Optional as _Optional

FEATURE_STATE_PATH = os.path.join(DATASET_DIR, "security_intelligence_state.json")

class AccessCheckRequest(_BaseModel):
    user_id: str
    operation: str = "VIEW"
    sensitivity: str = "MEDIUM"

class DecoyRequest(_BaseModel):
    user_id: str
    resource: str = "EXAM_ARCHIVE_DECOY"

class FeedbackRequest(_BaseModel):
    incident_id: str = ""
    label: str = "LEGITIMATE"
    note: str = ""
    user_id: str = ""

def _feature_state():
    try:
        with open(FEATURE_STATE_PATH, encoding="utf-8") as f:
            state = _json.load(f)
        return state if isinstance(state, dict) else {"decoys": [], "feedback": []}
    except (FileNotFoundError, ValueError, OSError):
        return {"decoys": [], "feedback": []}

def _save_feature_state(state):
    os.makedirs(DATASET_DIR, exist_ok=True)
    temp_path = FEATURE_STATE_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        _json.dump(state, f, indent=2)
    os.replace(temp_path, FEATURE_STATE_PATH)

def _user_record(user_id):
    matches = [u for u in _users_cache if u.get("user_id") == user_id]
    if not matches:
        raise HTTPException(404, "Unknown simulated user_id")
    status_rows = db.fetch_all("SELECT status FROM users WHERE user_id = ?", (user_id,))
    user = dict(matches[0])
    user["status"] = status_rows[0]["status"] if status_rows else "ACTIVE"
    return user

def _recent_user_events(user_id, limit=500):
    if user_id:
        rows = db.fetch_all("SELECT * FROM events WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit))
    else:
        rows = db.fetch_all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    parsed = []
    for row in rows:
        item = dict(row)
        try:
            item["detail"] = _json.loads(item.get("detail") or "{}")
        except (TypeError, ValueError):
            item["detail"] = {}
        parsed.append(item)
    return parsed

def _user_activity_risk(user_id):
    events = _recent_user_events(user_id, 250)
    score, reasons = 0, []
    downloads = sum(1 for e in events[:120] if e["event_type"] == "FILE_DOWNLOAD")
    failed = sum(1 for e in events[:120] if e["event_type"] == "LOGIN_FAILED")
    api_requests = sum(int(e["detail"].get("count", 1) or 1) for e in events[:120] if e["event_type"] == "API_REQUEST")
    decoys = sum(1 for e in events if e["detail"].get("decoy_resource"))
    if downloads >= 20:
        score += 30; reasons.append(f"High recent download volume ({downloads} events)")
    elif downloads >= 8:
        score += 15; reasons.append(f"Elevated recent download volume ({downloads} events)")
    if failed >= 5:
        score += 25; reasons.append(f"Repeated failed logins ({failed} events)")
    if api_requests >= 500:
        score += 25; reasons.append(f"High API request volume ({api_requests} requests)")
    if decoys:
        score += min(40, 25 * decoys); reasons.append(f"Decoy-resource interaction recorded ({decoys})")
    user = _user_record(user_id)
    if user["status"] == "BLOCKED":
        score = max(score, 90); reasons.append("Account is currently blocked")
    elif user["status"] == "FLAGGED":
        score = max(score, 55); reasons.append("Account is flagged for review")
    return min(100, score), reasons, {"downloads": downloads, "failed_logins": failed, "api_requests": api_requests, "decoy_hits": decoys}

@app.get("/api/security-intelligence/summary")
def security_intelligence_summary():
    state = _feature_state()
    events = _recent_user_events("", 500)
    decoys = state.get("decoys", [])
    feedback = state.get("feedback", [])
    return {
        "recent_evidence_events": len(events),
        "decoy_interactions": len(decoys),
        "reviewed_feedback": len(feedback),
        "role_baselines": {
            "Student": {"bulk_download_review_threshold": 8, "high_sensitivity_requires_review": True},
            "Guest": {"bulk_download_review_threshold": 3, "high_sensitivity_requires_review": True},
            "Faculty": {"bulk_download_review_threshold": 25, "high_sensitivity_requires_review": True},
            "HOD": {"bulk_download_review_threshold": 30, "high_sensitivity_requires_review": True},
            "Administrator": {"bulk_download_review_threshold": 40, "high_sensitivity_requires_review": True}
        }
    }

@app.post("/api/security-intelligence/access-check")
def security_intelligence_access_check(payload: AccessCheckRequest):
    user = _user_record(payload.user_id)
    role = user.get("role", "Guest")
    operation = payload.operation.upper()
    sensitivity = payload.sensitivity.upper()
    risk, reasons, metrics = _user_activity_risk(payload.user_id)
    role_permissions = {
        "Student": {"VIEW": True, "DOWNLOAD": True, "BULK_DOWNLOAD": True, "EXAM_ACCESS": False, "MANAGE_USERS": False},
        "Guest": {"VIEW": True, "DOWNLOAD": False, "BULK_DOWNLOAD": False, "EXAM_ACCESS": False, "MANAGE_USERS": False},
        "Faculty": {"VIEW": True, "DOWNLOAD": True, "BULK_DOWNLOAD": True, "EXAM_ACCESS": True, "MANAGE_USERS": False},
        "HOD": {"VIEW": True, "DOWNLOAD": True, "BULK_DOWNLOAD": True, "EXAM_ACCESS": True, "MANAGE_USERS": False},
        "Administrator": {"VIEW": True, "DOWNLOAD": True, "BULK_DOWNLOAD": True, "EXAM_ACCESS": True, "MANAGE_USERS": True},
    }
    role_allowed = role_permissions.get(role, {}).get(operation, False)
    policy_reasons = list(reasons)
    if not role_allowed:
        decision, action = "DENY", "Requested operation is not allowed for this role"
        policy_reasons.append(f"Role {role} does not have permission for {operation}")
    elif user["status"] == "BLOCKED" or risk >= 80:
        decision, action = "DENY", "High risk or blocked account; deny simulated request"
    elif operation == "BULK_DOWNLOAD" and risk >= 35:
        decision, action = "STEP_UP_AUTH", "Require re-authentication and temporarily restrict bulk downloads"
    elif sensitivity in ("HIGH", "CRITICAL") and risk >= 25:
        decision, action = "STEP_UP_AUTH", "Require re-authentication before sensitive access"
    elif operation == "BULK_DOWNLOAD" and role in ("Student", "Guest"):
        decision, action = "RESTRICT", "Bulk download is restricted by role-aware baseline"
    else:
        decision, action = "ALLOW", "Role permission and current risk policy allow this simulated operation"
    db.insert_audit("Adaptive Access Policy", f"{decision}: {operation}/{sensitivity}; risk={risk}", payload.user_id)
    return {"user_id": payload.user_id, "role": role, "operation": operation, "sensitivity": sensitivity,
            "risk_score": risk, "risk_level": "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 30 else "LOW",
            "decision": decision, "action": action, "reasons": policy_reasons or ["No elevated-risk indicators found in recent simulated events"], "activity_metrics": metrics,
            "simulation_only": True}

@app.post("/api/security-intelligence/decoy-access")
def security_intelligence_decoy_access(payload: DecoyRequest):
    _user_record(payload.user_id)
    resource = payload.resource.upper()
    allowed_resources = {"EXAM_ARCHIVE_DECOY", "STUDENT_RECORD_DECOY", "FACULTY_RESEARCH_DECOY"}
    if resource not in allowed_resources:
        raise HTTPException(400, "Unknown decoy resource")
    timestamp = _datetime.now(_timezone.utc).isoformat()
    detail = {"resource_id": resource, "sensitivity": "HIGH", "decoy_resource": True,
              "description": "Synthetic honeypot resource; no real academic data exists"}
    result = engine.process_event(payload.user_id, "FILE_VIEW", detail, timestamp=timestamp)
    state = _feature_state()
    record = {"timestamp": timestamp, "user_id": payload.user_id, "resource": resource,
              "signal": "INVESTIGATION_SIGNAL", "message": "Decoy access is suspicious evidence, not proof of compromise"}
    state.setdefault("decoys", []).insert(0, record)
    state["decoys"] = state["decoys"][:500]
    _save_feature_state(state)
    db.insert_audit("Academic Cloud Honeypot", f"Decoy interaction: {resource}", payload.user_id)
    return {"status": "recorded", "record": record, "assessment": result.get("assessment"), "incident": result.get("incident")}

@app.get("/api/security-intelligence/timeline")
def security_intelligence_timeline(user_id: str = ""):
    if user_id:
        _user_record(user_id)
    events = _recent_user_events(user_id, 250)
    state = _feature_state()
    timeline = []
    for event in events:
        detail = event.get("detail") or {}
        timeline.append({"timestamp": event.get("timestamp"), "user_id": event.get("user_id"),
                         "type": "DECOY" if detail.get("decoy_resource") else event.get("event_type", "EVENT"),
                         "source": "Academic Cloud Honeypot" if detail.get("decoy_resource") else "Event Monitor",
                         "description": detail.get("description") or detail.get("resource_id") or detail.get("endpoint") or event.get("event_type", "Event").replace("_", " ").title(),
                         "evidence": detail})
    for item in state.get("decoys", []):
        if not user_id or item.get("user_id") == user_id:
            timeline.append({"timestamp": item["timestamp"], "user_id": item["user_id"], "type": "DECOY",
                             "source": "Academic Cloud Honeypot", "description": f"Decoy resource accessed: {item['resource']}",
                             "evidence": {"signal": item["signal"]}})
    incidents = db.fetch_all("SELECT incident_id, user_id, timestamp, threat_score, classification, status FROM incidents ORDER BY timestamp DESC LIMIT 100")
    for incident in incidents:
        if not user_id or incident["user_id"] == user_id:
            timeline.append({"timestamp": incident["timestamp"], "user_id": incident["user_id"], "type": "INCIDENT",
                             "source": "Threat Analysis Agent", "description": f"{incident['classification']} incident {incident['incident_id']} · score {incident['threat_score']}/100",
                             "evidence": {"incident_id": incident["incident_id"], "status": incident["status"]}})
    timeline.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return timeline[:250]

@app.get("/api/security-intelligence/attack-path/{user_id}")
def security_intelligence_attack_path(user_id: str):
    user = _user_record(user_id)
    role = user.get("role", "Guest")
    access = {
        "Student": [("Own project files", "LOW", "Own files only"), ("Attendance records", "MEDIUM", "View-only / policy dependent")],
        "Guest": [("Public project resources", "LOW", "Restricted guest scope")],
        "Faculty": [("Department files", "MEDIUM", "Department-scoped"), ("Examination papers", "CRITICAL", "Authorized academic role")],
        "HOD": [("Department files", "MEDIUM", "Department-wide scope"), ("Examination papers", "CRITICAL", "Authorized academic role"), ("Attendance records", "HIGH", "Department oversight")],
        "Administrator": [("User directory", "HIGH", "Administrative scope"), ("Department files", "HIGH", "Broad operational scope"), ("Examination papers", "CRITICAL", "High-impact resource"), ("Permissions and accounts", "CRITICAL", "Privileged management")],
    }
    resources = access.get(role, access["Guest"])
    return {"user_id": user_id, "role": role, "account_status": user["status"],
            "reachable_resources": [{"resource": n, "risk": r, "access_scope": s} for n, r, s in resources],
            "blast_radius": "HIGH" if any(r == "CRITICAL" for _, r, _ in resources) else "MEDIUM" if len(resources) > 1 else "LOW",
            "recommendation": "Review least-privilege permissions and revoke unnecessary access first.",
            "simulation_only": True}

@app.get("/api/security-intelligence/confidence/{user_id}")
def security_intelligence_confidence(user_id: str):
    _user_record(user_id)
    risk, reasons, metrics = _user_activity_risk(user_id)
    events = _recent_user_events(user_id, 250)
    event_types = {e["event_type"] for e in events}
    signals = [
        {"agent": "Authentication Agent", "risk": min(100, 25 if metrics["failed_logins"] >= 5 else 0), "confidence": 0.90 if "LOGIN_FAILED" in event_types else 0.35, "evidence": f"{metrics['failed_logins']} failed login events in inspected sample"},
        {"agent": "Data Access Agent", "risk": min(100, 25 if metrics["downloads"] >= 8 else 0), "confidence": 0.88 if "FILE_DOWNLOAD" in event_types else 0.35, "evidence": f"{metrics['downloads']} download events in inspected sample"},
        {"agent": "Network Agent", "risk": min(100, 25 if metrics["api_requests"] >= 500 else 0), "confidence": 0.88 if "API_REQUEST" in event_types else 0.35, "evidence": f"{metrics['api_requests']} API requests in inspected sample"},
        {"agent": "Honeypot Signal", "risk": min(100, 40 if metrics["decoy_hits"] else 0), "confidence": 0.95 if metrics["decoy_hits"] else 0.0, "evidence": f"{metrics['decoy_hits']} decoy interactions recorded"},
    ]
    active = [s for s in signals if s["confidence"] >= 0.8]
    levels = [s["risk"] for s in active]
    disagreement = (max(levels) - min(levels)) if len(levels) > 1 else 0
    completeness = round(100 * len(active) / len(signals))
    if not active:
        recommendation = "INSUFFICIENT EVIDENCE — continue monitoring; do not infer compromise."
    elif disagreement >= 30:
        recommendation = "REVIEW — agent signals disagree; prefer step-up verification over automatic blocking."
    elif risk >= 60:
        recommendation = "HIGH RISK — apply proportionate simulated containment and inspect the timeline."
    else:
        recommendation = "MONITOR — keep the evidence trail and reassess if new signals arrive."
    return {"user_id": user_id, "overall_risk": risk, "evidence_completeness": completeness,
            "active_signal_count": len(active), "signal_disagreement": disagreement,
            "recommendation": recommendation, "agents": signals, "risk_reasons": reasons}

@app.post("/api/security-intelligence/feedback")
def security_intelligence_feedback(payload: FeedbackRequest):
    label = payload.label.upper()
    if label not in {"LEGITIMATE", "SUSPICIOUS"}:
        raise HTTPException(400, "label must be LEGITIMATE or SUSPICIOUS")
    if payload.user_id:
        _user_record(payload.user_id)
    state = _feature_state()
    record = {"timestamp": _datetime.now(_timezone.utc).isoformat(), "incident_id": payload.incident_id.strip(),
              "label": label, "note": payload.note.strip()[:500], "user_id": payload.user_id.strip(),
              "reviewer": "Local administrator"}
    state.setdefault("feedback", []).insert(0, record)
    state["feedback"] = state["feedback"][:1000]
    _save_feature_state(state)
    db.insert_audit("Security Review Feedback", f"Incident feedback labelled {label}", payload.user_id or "N/A")
    return {"status": "saved", "record": record, "message": "Feedback saved locally for review and baseline tuning; no automatic model retraining is claimed."}


# ----------------------------------------------------------------------
# FRONTEND (static dashboard)
# ----------------------------------------------------------------------
@app.get("/")
def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
