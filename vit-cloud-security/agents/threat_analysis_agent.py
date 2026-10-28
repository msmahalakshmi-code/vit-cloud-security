"""
AGENT 4 - THREAT ANALYSIS AGENT
----------------------------------
The central reasoning agent. Takes the independent AgentObservations
produced by Authentication, Data Access and Network agents, and combines
them into a single, explainable threat score + classification.

Combination rule (transparent, rule-based - matches project spec):

    Threat Score = min(100, sum of each agent's risk_score)

This is intentionally simple and explainable for a first prototype.
An optional ML anomaly score (Isolation Forest, see ml/anomaly_detector.py)
can later be blended in via `ml_bonus`.
"""

from dataclasses import dataclass, field
from typing import List
from datetime import datetime

from agents.authentication_agent import AgentObservation


@dataclass
class ThreatAssessment:
    user_id: str
    timestamp: str
    total_score: int
    classification: str          # LOW / MEDIUM / HIGH / CRITICAL
    observations: List[AgentObservation] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


class ThreatAnalysisAgent:
    name = "Threat Analysis Agent"

    THRESHOLDS = [
        (0, 30, "LOW"),
        (31, 60, "MEDIUM"),
        (61, 80, "HIGH"),
        (81, 100, "CRITICAL"),
    ]

    def classify(self, score: int) -> str:
        for low, high, label in self.THRESHOLDS:
            if low <= score <= high:
                return label
        return "CRITICAL"

    def combine(self, user_id: str, observations: List[AgentObservation],
                ml_bonus: int = 0) -> ThreatAssessment:
        raw_total = sum(o.risk_score for o in observations) + ml_bonus
        total = min(int(round(raw_total)), 100)
        classification = self.classify(total)

        evidence = []
        for obs in observations:
            evidence.extend(obs.reasons)

        return ThreatAssessment(
            user_id=user_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            total_score=total,
            classification=classification,
            observations=observations,
            evidence=evidence,
        )
