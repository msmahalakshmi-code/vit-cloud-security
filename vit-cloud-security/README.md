# VIT Cloud Security Center — Multi-Agent Cloud Security System

A working prototype for your **"Multi-Agent Cloud Security System for VIT"** project.
Five independent security agents monitor a simulated VIT cloud environment, combine
their observations into a single explainable threat score, and an automated Response
Agent acts on it — all shown live on a dashboard.

Everything here is **synthetic / simulated**. No real VIT systems, accounts, or data
are touched anywhere in this project.

---

## 1. What's inside

```
vit-cloud-security/
├── agents/
│   ├── authentication_agent.py   AGENT 1 — login/auth anomalies
│   ├── data_access_agent.py      AGENT 2 — file access/download anomalies
│   ├── network_agent.py          AGENT 3 — API/network traffic anomalies
│   ├── threat_analysis_agent.py  AGENT 4 — combines observations -> threat score
│   └── response_agent.py         AGENT 5 — decides + logs defensive actions
├── backend/
│   ├── main.py        FastAPI app + REST endpoints + background traffic
│   ├── engine.py       Orchestrator: events -> agents -> incidents
│   └── database.py     SQLite storage
├── simulator/
│   ├── generate_data.py       Synthetic VIT dataset generator (users, logs)
│   └── realtime_simulator.py  Normal traffic + the 5 attack scenarios
├── ml/
│   ├── anomaly_detector.py         Optional Isolation Forest on your synthetic data
│   └── public_dataset_runner.py    Feeds CICIDS2017 / UNSW-NB15 through ALL 5 agents
├── frontend/           Dashboard (HTML/CSS/JS, no build step)
├── dataset/            Generated CSVs + SQLite DB land here
└── requirements.txt
```

## 2. Requirements

- Python 3.10+
- VS Code (or any editor) + a terminal

## 3. Setup (run once)

```bash
cd vit-cloud-security
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

## 4. Generate the synthetic VIT dataset

```bash
python simulator/generate_data.py
```

This creates `dataset/users.csv`, `login_logs.csv`, `file_access_logs.csv`,
`network_logs.csv`, `permissions.csv` — ~100 simulated users (students, faculty,
HODs, admins, guests) with 14,000+ log rows, including injected suspicious
sessions for a handful of users. Safe to re-run any time.

## 5. Run the backend + dashboard

```bash
uvicorn backend.main:app --reload --port 8000
```

Open **http://127.0.0.1:8000** — that's the dashboard. API docs (auto-generated)
are at http://127.0.0.1:8000/docs.

The backend auto-generates the dataset on first run if it's missing, seeds
SQLite, and starts a background thread that trickles ordinary "normal" traffic
so the dashboard feels alive even before you trigger anything.

## 6. Trigger the 5 project-spec attack scenarios

Go to the **Simulate Attack** tab and click any of the 5 cards, or call the API
directly:

```bash
curl -X POST http://127.0.0.1:8000/api/simulate/compromised_account
curl -X POST http://127.0.0.1:8000/api/simulate/unauthorized_academic_access
curl -X POST http://127.0.0.1:8000/api/simulate/excessive_download
curl -X POST http://127.0.0.1:8000/api/simulate/bruteforce_login
curl -X POST http://127.0.0.1:8000/api/simulate/api_burst
```

Watch **Overview** and **Incidents** update within a couple of seconds. Click
any incident to see exactly which agents flagged what, the evidence, the
combined threat score, and the actions the Response Agent took.

To wipe all events/incidents and start clean: `POST /api/reset`.

---

## 7. Running the public datasets you downloaded (CICIDS2017 / UNSW-NB15)

These are **network-flow datasets only** (no VIT logins or file access), so
they validate the **Network Agent's** thresholds against real, independently
labelled attack traffic. Every flow window is still pushed through
`engine.process_event(...)`, which **always runs all 5 agents** — Authentication
and Data Access will mostly report LOW on this data (expected: there's no
login/file signal for them to react to), which is itself useful evidence in
your report that the agents don't false-positive on signals they have no
evidence for.

1. Put your downloaded CSV anywhere, e.g. `dataset/public/`.
2. With the backend running (step 5 above, so you can watch it live), open a
   **second terminal**, activate the same venv, and run:

```bash
# CICIDS2017
python ml/public_dataset_runner.py --dataset cicids --file dataset/public/YOUR_FILE.csv --limit 20000

# UNSW-NB15
python ml/public_dataset_runner.py --dataset unsw --file dataset/public/YOUR_FILE.csv --limit 20000
```

- `--limit 20000` processes only the first 20,000 rows — good for a fast first
  run, since some CICIDS2017 daily files have 500,000+ rows. Drop it (or raise
  it) once you're happy with the result.
- `--rows-per-window 50` (default) controls how many raw flow rows are merged
  into one simulated request event — lower it (e.g. `20`) if your file's
  attack rows are sparse and you want them to concentrate more per window.
- The script auto-detects column names (handles the slightly different headers
  CICIDS2017 CSVs ship with, and UNSW-NB15's `label`/`attack_cat` columns).
- Results write into the same `dataset/vit_cloud_security.db` the dashboard
  reads from, tagged as synthetic users `PUB-CICIDS-01..06` / `PUB-UNSW-01..06`
  — refresh the dashboard and you'll see them appear under Users/Incidents.

### Where to get the datasets

- **CICIDS2017** (Canadian Institute for Cybersecurity):
  https://www.unb.ca/cic/datasets/ids-2017.html
  Download any of the labelled daily CSVs (e.g. `Wednesday-workingHours.pcap_ISCX.csv`
  has a large DoS block, `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  has a big PortScan block — good ones to try first).
- **UNSW-NB15** (UNSW Canberra Cyber):
  https://research.unsw.edu.au/projects/unsw-nb15-dataset
  Use `UNSW_NB15_training-set.csv` or `UNSW_NB15_testing-set.csv`.

Both are standard, freely available academic intrusion-detection datasets —
appropriate for citing in your report as external validation of the Network
Agent, per Section 5/7 of the original project brief.

## 8. Optional: Isolation Forest on your synthetic dataset (Phase 14)

```bash
python ml/anomaly_detector.py
```

Trains an unsupervised Isolation Forest on per-user-per-day behavioural
features from your synthetic logs and writes `dataset/ml_anomaly_scores.csv`.
This is a second, ML-based validation angle for your report — it is **not**
wired into the live dashboard by default, since the rule-based agents already
give a transparent, explainable score, which matters more for a viva than a
black-box model. You can blend it in later via
`ThreatAnalysisAgent.combine(..., ml_bonus=...)` if you want to show both
combined.

---

## 9. How the pipeline fits together

```
VIT CLOUD SIMULATOR (or public dataset runner)
        |
Login Events / File Events / Network Events
        |
Authentication Agent   Data Access Agent   Network Agent   <- run on EVERY event
        \                    |                /
                 Threat Analysis Agent   (Score = sum of agent scores, capped 0-100)
                        |
        0-30 LOW · 31-60 MEDIUM · 61-80 HIGH · 81-100 CRITICAL
                        |
                  Response Agent
                        |
        Actions + Incident Record + Audit Log Entry
                        |
                 Dashboard (this app)
```

## 10. Notes for your report / viva

- Threat scoring is deliberately **rule-based and explainable** first (Phase 9
  of your roadmap) — every score can be traced back to specific evidence
  lines shown in the incident modal. The optional Isolation Forest model is a
  separate, complementary validation layer, matching Section 9's guidance not
  to jump straight to a black box.
- SQLite is used instead of PostgreSQL for zero-setup local development; the
  schema (`backend/database.py`) is written close enough to a normal relational
  schema that swapping the driver later is a small, well-scoped change, not a
  redesign.
- Nothing in this project sends requests to, or reads data from, real VIT
  infrastructure. All users, logs, and incidents are synthetic or derived from
  the public CICIDS2017/UNSW-NB15 datasets.


---

## 11. Security Intelligence page (enhanced build)

The navigation now includes **Security Intelligence**, a single page containing six simulated capabilities:

1. **Adaptive risk-based access** — role permission + recent activity + sensitivity policy evaluation. Outcomes include ALLOW, DENY, RESTRICT or STEP_UP_AUTH-style decisions.
2. **Threat investigation timeline** — chronological view of stored events, incidents and decoy interactions.
3. **Academic cloud honeypot** — controlled synthetic decoy-resource interactions, recorded as investigation signals.
4. **Attack-path / blast-radius analysis** — role-derived resource reachability estimates and least-privilege recommendations.
5. **Behaviour baselines and feedback** — role-aware reference thresholds and locally saved reviewer labels.
6. **Confidence-aware agent decisions** — displays signal coverage, evidence confidence and guidance when evidence is sparse or signals disagree.

### Run

From the `vit-cloud-security` directory with your virtual environment activated:

```powershell
python -m pip install -r requirements.txt
python simulator/generate_data.py
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/`. Click **Security Intelligence** in the left navigation. API documentation is available at `http://127.0.0.1:8080/docs`.

The new feedback state is saved to `dataset/security_intelligence_state.json`. All access checks and decoy events are simulated. The baseline feedback is recorded for review; it does not claim automatic ML retraining. Attack-path analysis is a role-based prototype, not a live cloud IAM graph. No existing cloud service is modified.
