"""
The Engine is the glue between raw events and the 5 agents.

For every incoming event it:
  1. Updates a rolling "current window" stats snapshot for that user
     (window = last WINDOW_SECONDS seconds of activity).
  2. Asks Authentication / Data Access / Network agents to evaluate
     their slice of the window.
  3. Passes their AgentObservations to the Threat Analysis Agent.
  4. If the resulting score crosses ALERT_THRESHOLD, asks the Response
     Agent what to do, writes an incident + audit log entries, and
     (if BLOCKED) marks the simulated user account as blocked.

This mirrors the architecture diagram in the project spec:
Events -> [Auth, Data, Network agents] -> Threat Analysis Agent -> Response Agent
"""

import uuid
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from agents.authentication_agent import AuthenticationAgent
from agents.data_access_agent import DataAccessAgent
from agents.network_agent import NetworkAgent
from agents.threat_analysis_agent import ThreatAnalysisAgent
from agents.response_agent import ResponseAgent

from backend import database as db

WINDOW_SECONDS = 120          # rolling window used to compute "current" stats
ALERT_THRESHOLD = 61          # HIGH and above triggers an incident record
INCIDENT_COOLDOWN_SECONDS = 20  # avoid one incident per event during a burst


class Engine:
    def __init__(self):
        self.auth_agent = AuthenticationAgent()
        self.data_agent = DataAccessAgent()
        self.net_agent = NetworkAgent()
        self.threat_agent = ThreatAnalysisAgent()
        self.response_agent = ResponseAgent()

        # per-user deque of (timestamp_epoch, event_dict)
        self._history = defaultdict(deque)
        # cached known devices / ips per user, to detect "new"
        self._known_devices = defaultdict(set)
        self._known_ips = defaultdict(set)
        # cooldown so a single attack burst (dozens of events in a few
        # seconds) creates ONE incident instead of one per event
        self._last_incident_at = {}
        self._last_medium_log_at = {}

        self.agent_status = {
            "Authentication Agent": "ACTIVE",
            "Data Access Agent": "ACTIVE",
            "Network Agent": "ACTIVE",
            "Threat Analysis Agent": "ACTIVE",
            "Response Agent": "ACTIVE",
        }

    # ------------------------------------------------------------------
    def process_event(self, user_id: str, event_type: str, detail: dict, timestamp: str = None):
        ts = timestamp or (datetime.now(timezone.utc).isoformat() + "Z")
        now_epoch = time.time()

        db.insert_event(ts, user_id, event_type, detail)

        hist = self._history[user_id]
        hist.append((now_epoch, event_type, detail))
        # drop anything outside the rolling window
        while hist and now_epoch - hist[0][0] > WINDOW_SECONDS:
            hist.popleft()

        stats = self._compute_window_stats(user_id, hist, detail)

        auth_obs = self.auth_agent.evaluate(stats)
        data_obs = self.data_agent.evaluate(stats)
        net_obs = self.net_agent.evaluate(stats)

        assessment = self.threat_agent.combine(user_id, [auth_obs, data_obs, net_obs])

        incident = None
        if assessment.total_score >= ALERT_THRESHOLD:
            last = self._last_incident_at.get(user_id, 0)
            within_cooldown = (now_epoch - last) < INCIDENT_COOLDOWN_SECONDS

            response = self.response_agent.decide(assessment)

            if response.status == "BLOCKED":
                # always keep the account/user status in sync even during cooldown
                db.set_user_status(user_id, "BLOCKED")
            elif response.status == "ALERTED":
                db.set_user_status(user_id, "FLAGGED")

            if within_cooldown:
                return {
                    "assessment": self._assessment_payload(assessment, auth_obs, data_obs, net_obs),
                    "incident": None,
                }

            self._last_incident_at[user_id] = now_epoch
            incident_id = f"VIT-{uuid.uuid4().hex[:6].upper()}"

            incident = {
                "incident_id": incident_id,
                "user_id": user_id,
                "timestamp": assessment.timestamp,
                "threat_score": assessment.total_score,
                "classification": assessment.classification,
                "detected_by": [
                    {"agent": o.agent, "score": o.risk_score, "level": o.level}
                    for o in [auth_obs, data_obs, net_obs]
                ],
                "evidence": assessment.evidence,
                "actions": response.actions,
                "status": response.status,
            }
            db.insert_incident(incident)
            db.insert_audit("Response Agent", f"{response.status}: {', '.join(response.actions)}", user_id)

        else:
            # still log light-touch monitoring to the audit trail occasionally,
            # but throttled so a burst of medium-risk events doesn't flood the log
            if assessment.total_score >= 31:
                last = self._last_medium_log_at.get(user_id, 0)
                if (now_epoch - last) >= INCIDENT_COOLDOWN_SECONDS:
                    self._last_medium_log_at[user_id] = now_epoch
                    db.insert_audit("Threat Analysis Agent",
                                     f"MEDIUM risk observed (score {assessment.total_score})", user_id)

        return {
            "assessment": self._assessment_payload(assessment, auth_obs, data_obs, net_obs),
            "incident": incident,
        }

    @staticmethod
    def _assessment_payload(assessment, auth_obs, data_obs, net_obs):
        return {
            "user_id": assessment.user_id,
            "timestamp": assessment.timestamp,
            "total_score": assessment.total_score,
            "classification": assessment.classification,
            "observations": [
                {"agent": o.agent, "score": o.risk_score, "level": o.level, "reasons": o.reasons}
                for o in [auth_obs, data_obs, net_obs]
            ],
        }

    # ------------------------------------------------------------------
    def _compute_window_stats(self, user_id, hist, latest_detail):
        failed_logins = sum(1 for _, et, _ in hist if et == "LOGIN_FAILED")
        successful_logins = sum(1 for _, et, _ in hist if et == "LOGIN_SUCCESS")
        files_accessed = sum(1 for _, et, _ in hist if et == "FILE_VIEW")
        downloads = sum(1 for _, et, _ in hist if et == "FILE_DOWNLOAD")
        unauthorized = sum(1 for _, et, d in hist if et == "FILE_DENIED")
        sensitive = sum(1 for _, et, d in hist if et in ("FILE_VIEW", "FILE_DOWNLOAD")
                         and d.get("sensitivity") == "HIGH")
        api_events = [d for _, et, d in hist if et == "API_REQUEST"]
        request_count = sum(d.get("count", 1) for d in api_events)
        error_events = sum(1 for d in api_events if d.get("error"))
        error_rate = (error_events / len(api_events)) if api_events else 0
        endpoints = len(set(d.get("endpoint", "") for d in api_events)) if api_events else 0

        device = latest_detail.get("device_id")
        ip = latest_detail.get("ip_address")
        new_device = False
        new_ip = False
        if device:
            new_device = device not in self._known_devices[user_id]
            self._known_devices[user_id].add(device)
        if ip:
            new_ip = ip not in self._known_ips[user_id]
            self._known_ips[user_id].add(ip)

        hour = None
        if "hour" in latest_detail:
            hour = latest_detail["hour"]
        else:
            hour = datetime.now(timezone.utc).hour

        return {
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "new_device": new_device,
            "new_ip": new_ip,
            "last_login_hour": hour,
            "files_accessed": files_accessed,
            "downloads": downloads,
            "unauthorized_attempts": unauthorized,
            "sensitive_files_touched": sensitive,
            "request_count": request_count,
            "error_rate": error_rate,
            "distinct_endpoints_hit": endpoints,
        }


# a single shared engine instance for the running backend process
engine = Engine()
