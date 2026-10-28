"""
AGENT 3 - NETWORK / API TRAFFIC AGENT
---------------------------------------
Watches a user/device's simulated API request rate for bursts, and can
optionally be validated later against public network-intrusion datasets
(CICIDS2017 / UNSW-NB15) - see README for links. For the prototype it
runs entirely on rule thresholds over the synthetic request-count feature.
"""

from dataclasses import dataclass, field
from typing import List

from agents.authentication_agent import AgentObservation


class NetworkAgent:
    name = "Network Agent"

    NORMAL_REQUESTS = 30          # baseline requests per window
    WEIGHT_PER_50_EXTRA = 10
    MAX_TRAFFIC_SCORE = 40
    WEIGHT_HIGH_ERROR_RATE = 15
    WEIGHT_SCAN_PATTERN = 20

    def evaluate(self, user_stats: dict) -> AgentObservation:
        """
        user_stats example:
        {
            "request_count": 900,
            "error_rate": 0.4,          # fraction of non-2xx responses
            "distinct_endpoints_hit": 40,  # many distinct endpoints quickly => scanning
        }
        """
        score = 0
        reasons = []

        requests = user_stats.get("request_count", 0)
        if requests > self.NORMAL_REQUESTS:
            excess = requests - self.NORMAL_REQUESTS
            traffic_score = min((excess / 50) * self.WEIGHT_PER_50_EXTRA,
                                 self.MAX_TRAFFIC_SCORE)
            score += traffic_score
            if requests >= 150:
                reasons.append(f"{requests} API requests in current window (baseline ~{self.NORMAL_REQUESTS})")

        error_rate = user_stats.get("error_rate", 0)
        if error_rate >= 0.3:
            score += self.WEIGHT_HIGH_ERROR_RATE
            reasons.append(f"High error/rejection rate on requests ({error_rate:.0%})")

        endpoints = user_stats.get("distinct_endpoints_hit", 0)
        if endpoints >= 15:
            score += self.WEIGHT_SCAN_PATTERN
            reasons.append(f"{endpoints} distinct endpoints hit quickly (possible scanning behaviour)")

        score = min(int(round(score)), 100)
        level = "LOW" if score < 31 else "MEDIUM" if score < 61 else "HIGH"

        return AgentObservation(agent=self.name, risk_score=score, level=level, reasons=reasons)
