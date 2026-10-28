"""
PHASE 11 - Real-time security event simulator.

Instead of only replaying a static CSV, this module can emit events live
(with small delays) so the dashboard updates the way a real monitoring
system would. Two modes:

  - normal_event(user)          -> one ordinary login/file/network event
  - SCENARIOS[name](user)       -> a full ordered attack sequence, e.g.
                                    "compromised_account", matching the
                                    project spec's Scenario 1-5.

Every event is a (event_type, detail_dict) tuple. The caller (backend
main.py) is responsible for spacing them out in time and calling
engine.process_event(...) for each.
"""

import random
import uuid


def normal_event(user: dict):
    """One ordinary event for a user going about their day."""
    choice = random.choices(
        ["LOGIN_SUCCESS", "FILE_VIEW", "FILE_DOWNLOAD", "API_REQUEST"],
        weights=[10, 40, 15, 35],
    )[0]

    if choice == "LOGIN_SUCCESS":
        detail = {"device_id": user["home_device"], "ip_address": user["home_ip"], "hour": random.randint(8, 20)}
    elif choice in ("FILE_VIEW", "FILE_DOWNLOAD"):
        detail = {"file_id": f"file-{uuid.uuid4().hex[:6]}", "sensitivity": "LOW"}
    else:
        detail = {"count": random.randint(1, 3), "endpoint": f"/api/resource{random.randint(1,5)}", "error": False}

    return choice, detail


# ---------------------------------------------------------------------
# ATTACK / SUSPICIOUS SCENARIOS (Section 4 of the project spec)
# ---------------------------------------------------------------------

def scenario_compromised_account(user: dict):
    """Scenario 1 - failed logins -> new device success -> mass file access/download -> API burst."""
    events = []
    fails = random.randint(20, 50)
    events.append(("LOGIN_FAILED", {"device_id": "DEV-UNKNOWN", "ip_address": "203.0.113.7", "hour": 2}))
    # represent the burst of fails as repeated identical events, engine counts them in the window
    for _ in range(fails - 1):
        events.append(("LOGIN_FAILED", {"device_id": "DEV-UNKNOWN", "ip_address": "203.0.113.7", "hour": 2}))
    events.append(("LOGIN_SUCCESS", {"device_id": f"DEV-{uuid.uuid4().hex[:6]}", "ip_address": "203.0.113.7", "hour": 2}))
    for _ in range(random.randint(120, 200)):
        events.append(("FILE_VIEW", {"file_id": f"file-{uuid.uuid4().hex[:6]}", "sensitivity": "LOW"}))
    for _ in range(random.randint(60, 100)):
        events.append(("FILE_DOWNLOAD", {"file_id": f"file-{uuid.uuid4().hex[:6]}", "sensitivity": "LOW"}))
    events.append(("API_REQUEST", {"count": random.randint(400, 900), "endpoint": "/api/files", "error": True}))
    return events


def scenario_unauthorized_academic_access(user: dict):
    """Scenario 2 - attempt to access examination paper / restricted document."""
    return [
        ("FILE_DENIED", {"file_id": "exam_paper.pdf", "sensitivity": "HIGH"}),
        ("FILE_VIEW", {"file_id": "exam_paper.pdf", "sensitivity": "HIGH"}),
    ]


def scenario_excessive_download(user: dict):
    """Scenario 3 - normal user suddenly downloads hundreds of files."""
    events = []
    for _ in range(random.randint(150, 250)):
        events.append(("FILE_DOWNLOAD", {"file_id": f"file-{uuid.uuid4().hex[:6]}", "sensitivity": "LOW"}))
    return events


def scenario_bruteforce_login(user: dict):
    """Scenario 4 - repeated failed logins followed by a successful one, no other anomaly."""
    events = []
    fails = random.randint(15, 40)
    for _ in range(fails):
        events.append(("LOGIN_FAILED", {"device_id": user["home_device"], "ip_address": user["home_ip"], "hour": 3}))
    events.append(("LOGIN_SUCCESS", {"device_id": user["home_device"], "ip_address": user["home_ip"], "hour": 3}))
    return events


def scenario_api_burst(user: dict):
    """Scenario 5 - abnormal API/request burst, e.g. scripted scraping or scanning."""
    return [
        ("API_REQUEST", {"count": random.randint(500, 1000),
                          "endpoint": f"/api/scan{random.randint(1,50)}", "error": True}),
    ]


SCENARIOS = {
    "compromised_account": scenario_compromised_account,
    "unauthorized_academic_access": scenario_unauthorized_academic_access,
    "excessive_download": scenario_excessive_download,
    "bruteforce_login": scenario_bruteforce_login,
    "api_burst": scenario_api_burst,
}
