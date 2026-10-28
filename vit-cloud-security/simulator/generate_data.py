"""
PHASE 4 / PHASE 6 - Synthetic VIT cloud security dataset generator.

Creates safe, fully fictional data (no real VIT data anywhere):
  dataset/users.csv
  dataset/login_logs.csv
  dataset/file_access_logs.csv
  dataset/network_logs.csv
  dataset/permissions.csv

Run:
    python simulator/generate_data.py

Produces ~5,000+ log rows across the three log files, mixing normal
behaviour with a smaller number of injected suspicious sessions so the
dataset is useful both for demoing the rule-based agents and for later
training the optional Isolation Forest anomaly detector.
"""

import csv
import os
import random
import uuid
from datetime import datetime, timedelta

random.seed(42)

HERE = os.path.dirname(__file__)
DATASET_DIR = os.path.join(HERE, "..", "dataset")
os.makedirs(DATASET_DIR, exist_ok=True)

ROLES = {
    "Student": 60,
    "Faculty": 20,
    "HOD": 8,
    "Administrator": 5,
    "Guest": 7,
}
DEPARTMENTS = ["CSE", "ECE", "MECH", "CIVIL", "BIOTECH", "IT"]

FILE_TYPES = {
    "Student": [("project_report.pdf", "MEDIUM"), ("assignment.docx", "LOW"), ("attendance.csv", "LOW")],
    "Faculty": [("course_material.pptx", "LOW"), ("student_grades.xlsx", "HIGH"), ("research_paper.pdf", "MEDIUM")],
    "HOD": [("dept_budget.xlsx", "HIGH"), ("faculty_review.docx", "HIGH"), ("dept_report.pdf", "MEDIUM")],
    "Administrator": [("admin_policy.pdf", "MEDIUM"), ("user_accounts.csv", "HIGH")],
    "Guest": [("public_brochure.pdf", "LOW")],
}
SENSITIVE_ONLY_FOR = {"exam_paper.pdf": ("HIGH", ["Faculty", "HOD", "Administrator"])}


def make_users():
    users = []
    counters = {"Student": 0, "Faculty": 0, "HOD": 0, "Administrator": 0, "Guest": 0}
    prefix = {"Student": "STU", "Faculty": "FAC", "HOD": "HOD", "Administrator": "ADM", "Guest": "GST"}
    for role, count in ROLES.items():
        for _ in range(count):
            counters[role] += 1
            user_id = f"{prefix[role]}{counters[role]:03d}"
            users.append({
                "user_id": user_id,
                "name": f"{role} {counters[role]}",
                "role": role,
                "department": random.choice(DEPARTMENTS),
                "home_device": f"DEV-{uuid.uuid4().hex[:8]}",
                "home_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            })
    return users


def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def generate_logs(users, days=14, suspicious_user_ratio=0.06):
    login_rows, file_rows, network_rows = [], [], []
    suspicious_users = set(random.sample([u["user_id"] for u in users],
                                          max(1, int(len(users) * suspicious_user_ratio))))

    base_time = datetime.utcnow() - timedelta(days=days)

    for day in range(days):
        for user in users:
            day_time = base_time + timedelta(days=day, hours=random.randint(7, 21))
            is_suspicious_day = user["user_id"] in suspicious_users and random.random() < 0.35

            if not is_suspicious_day:
                # ---- NORMAL DAY ----
                logins = random.randint(1, 2)
                for _ in range(logins):
                    ts = day_time + timedelta(minutes=random.randint(0, 400))
                    login_rows.append(_login_row(user, ts, status="SUCCESS", failed_before=0,
                                                   new_device=False))
                files_touched = random.randint(3, 10)
                for _ in range(files_touched):
                    ts = day_time + timedelta(minutes=random.randint(0, 400))
                    file_rows.append(_file_row(user, ts, action=random.choice(["VIEW", "VIEW", "DOWNLOAD"]),
                                                 authorized=True))
                req_count = random.randint(10, 30)
                network_rows.append(_network_row(user, day_time, req_count, error=False))

            else:
                # ---- SUSPICIOUS DAY (compromised-account style pattern) ----
                fail_count = random.randint(15, 60)
                fail_time = day_time
                login_rows.append(_login_row(user, fail_time, status="FAILED",
                                               failed_before=fail_count, new_device=False, count=fail_count))
                success_time = fail_time + timedelta(minutes=random.randint(1, 5))
                login_rows.append(_login_row(user, success_time, status="SUCCESS",
                                               failed_before=fail_count, new_device=True))

                files_touched = random.randint(80, 300)
                for i in range(min(files_touched, 40)):  # cap rows written, but reflect true count in one burst row
                    ts = success_time + timedelta(seconds=i * 5)
                    file_rows.append(_file_row(user, ts, action="VIEW", authorized=True))
                downloads = random.randint(40, 150)
                for i in range(min(downloads, 25)):
                    ts = success_time + timedelta(seconds=i * 7)
                    file_rows.append(_file_row(user, ts, action="DOWNLOAD", authorized=True))

                # occasional unauthorized attempt on a sensitive file
                if random.random() < 0.5:
                    ts = success_time + timedelta(minutes=2)
                    file_rows.append(_file_row(user, ts, action="VIEW", authorized=False, force_sensitive=True))

                req_count = random.randint(300, 1200)
                network_rows.append(_network_row(user, success_time, req_count, error=True))

    return login_rows, file_rows, network_rows, suspicious_users


def _login_row(user, ts, status, failed_before, new_device, count=1):
    return {
        "user_id": user["user_id"],
        "role": user["role"],
        "timestamp": ts.isoformat(),
        "login_status": status,
        "ip_address": user["home_ip"] if not new_device else f"172.16.{random.randint(0,255)}.{random.randint(1,254)}",
        "device_id": user["home_device"] if not new_device else f"DEV-{uuid.uuid4().hex[:8]}",
        "failed_attempts": failed_before,
        "new_device": new_device,
        "session_id": uuid.uuid4().hex[:12],
    }


def _file_row(user, ts, action, authorized, force_sensitive=False):
    catalog = FILE_TYPES.get(user["role"], FILE_TYPES["Student"])
    if force_sensitive or not authorized:
        fname, sensitivity = "exam_paper.pdf", "HIGH"
    else:
        fname, sensitivity = random.choice(catalog)
    return {
        "user_id": user["user_id"],
        "file_id": f"{fname}-{uuid.uuid4().hex[:6]}",
        "file_type": fname.split(".")[-1],
        "action": action,
        "timestamp": ts.isoformat(),
        "sensitivity": sensitivity,
        "owner": user["department"],
        "access_result": "ALLOWED" if authorized else "DENIED",
    }


def _network_row(user, ts, request_count, error):
    return {
        "timestamp": ts.isoformat(),
        "user_id": user["user_id"],
        "source_ip": user["home_ip"],
        "destination": "vit-cloud-api.internal",
        "request_count": request_count,
        "request_type": "REST",
        "response_code": "5xx/4xx-mixed" if error else "200",
        "bytes_sent": request_count * random.randint(200, 900),
        "duration": round(random.uniform(0.5, 40.0), 2),
    }


def main():
    users = make_users()
    write_csv(os.path.join(DATASET_DIR, "users.csv"), users,
              ["user_id", "name", "role", "department", "home_device", "home_ip"])

    login_rows, file_rows, network_rows, suspicious_users = generate_logs(users)

    write_csv(os.path.join(DATASET_DIR, "login_logs.csv"), login_rows,
              ["user_id", "role", "timestamp", "login_status", "ip_address", "device_id",
               "failed_attempts", "new_device", "session_id"])
    write_csv(os.path.join(DATASET_DIR, "file_access_logs.csv"), file_rows,
              ["user_id", "file_id", "file_type", "action", "timestamp", "sensitivity",
               "owner", "access_result"])
    write_csv(os.path.join(DATASET_DIR, "network_logs.csv"), network_rows,
              ["timestamp", "user_id", "source_ip", "destination", "request_count",
               "request_type", "response_code", "bytes_sent", "duration"])

    permissions = []
    for u in users:
        permissions.append({
            "role": u["role"],
            "can_view_own_files": True,
            "can_view_dept_files": u["role"] in ("Faculty", "HOD", "Administrator"),
            "can_view_exam_papers": u["role"] in ("Faculty", "HOD", "Administrator"),
            "can_manage_users": u["role"] == "Administrator",
        })
    write_csv(os.path.join(DATASET_DIR, "permissions.csv"), permissions,
              ["role", "can_view_own_files", "can_view_dept_files", "can_view_exam_papers", "can_manage_users"])

    total_rows = len(login_rows) + len(file_rows) + len(network_rows)
    print(f"Generated {len(users)} users")
    print(f"Generated {len(login_rows)} login rows, {len(file_rows)} file-access rows, "
          f"{len(network_rows)} network rows  (total {total_rows} log rows)")
    print(f"Injected suspicious-day patterns for users: {sorted(suspicious_users)}")
    print(f"Files written to: {os.path.abspath(DATASET_DIR)}")


if __name__ == "__main__":
    main()
