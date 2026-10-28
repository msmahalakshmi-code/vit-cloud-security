"""
PHASE 14 (optional) - ML-based anomaly detection to complement the
rule-based agents.

Algorithm: Isolation Forest (scikit-learn)
Why Isolation Forest and not something heavier:
  - Unsupervised: we don't have reliably labelled "attack" data for a
    brand-new simulated environment, only rough behavioural features.
  - Built specifically to isolate rare/short-path outliers, which is
    exactly what a compromised-account burst looks like in feature space.
  - Cheap to train/run, easy to explain in a viva ("shorter average path
    length in the trees = more anomalous").

This script builds a per-user-per-day behaviour feature table from the
synthetic logs (dataset/login_logs.csv, file_access_logs.csv,
network_logs.csv) and trains/evaluates the model. It is NOT wired into
the live FastAPI app by default - the rule-based agents already give a
transparent, explainable score for the prototype. Use this to (a) show
a second, ML-based validation angle in your report, and (b) optionally
blend `anomaly_score` into ThreatAnalysisAgent.combine(..., ml_bonus=...).

Run:
    python ml/anomaly_detector.py
"""

import os
import pandas as pd
from sklearn.ensemble import IsolationForest

HERE = os.path.dirname(__file__)
DATASET_DIR = os.path.join(HERE, "..", "dataset")


def build_features():
    logins = pd.read_csv(os.path.join(DATASET_DIR, "login_logs.csv"), parse_dates=["timestamp"])
    files = pd.read_csv(os.path.join(DATASET_DIR, "file_access_logs.csv"), parse_dates=["timestamp"])
    network = pd.read_csv(os.path.join(DATASET_DIR, "network_logs.csv"), parse_dates=["timestamp"])

    for df in (logins, files, network):
        df["date"] = df["timestamp"].dt.date

    login_feat = logins.groupby(["user_id", "date"]).agg(
        login_count=("login_status", "count"),
        failed_login_count=("failed_attempts", "max"),
        new_device=("new_device", "max"),
    ).reset_index()

    file_feat = files.groupby(["user_id", "date"]).agg(
        files_accessed=("action", lambda s: (s == "VIEW").sum()),
        files_downloaded=("action", lambda s: (s == "DOWNLOAD").sum()),
    ).reset_index()

    net_feat = network.groupby(["user_id", "date"]).agg(
        request_count=("request_count", "sum"),
    ).reset_index()

    feats = login_feat.merge(file_feat, on=["user_id", "date"], how="outer") \
                       .merge(net_feat, on=["user_id", "date"], how="outer") \
                       .fillna(0)
    return feats


def train_and_score(feats: pd.DataFrame):
    feature_cols = ["login_count", "failed_login_count", "new_device",
                     "files_accessed", "files_downloaded", "request_count"]
    X = feats[feature_cols]

    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,   # expect ~8% of user-days to be anomalous, tune as needed
        random_state=42,
    )
    model.fit(X)

    feats["anomaly_raw_score"] = model.decision_function(X)   # higher = more normal
    feats["is_anomaly"] = model.predict(X) == -1              # True = flagged as outlier

    # convert to a 0-100 "risk-style" score, inverted so higher = more suspicious
    min_s, max_s = feats["anomaly_raw_score"].min(), feats["anomaly_raw_score"].max()
    feats["anomaly_score_0_100"] = ((max_s - feats["anomaly_raw_score"]) / (max_s - min_s) * 100).round(1)

    return feats, model


def main():
    feats = build_features()
    scored, _ = train_and_score(feats)
    scored = scored.sort_values("anomaly_score_0_100", ascending=False)

    out_path = os.path.join(DATASET_DIR, "ml_anomaly_scores.csv")
    scored.to_csv(out_path, index=False)

    print(f"Scored {len(scored)} user-day records")
    print(f"Flagged as anomalous by Isolation Forest: {int(scored['is_anomaly'].sum())}")
    print("\nTop 10 most anomalous user-days:")
    print(scored[["user_id", "date", "anomaly_score_0_100", "is_anomaly"]].head(10).to_string(index=False))
    print(f"\nFull scored table written to: {os.path.abspath(out_path)}")


if __name__ == "__main__":
    main()
