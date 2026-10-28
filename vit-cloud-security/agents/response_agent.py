"""
AGENT 5 - RESPONSE AGENT
--------------------------
Takes a ThreatAssessment and decides which SAFE, SIMULATED defensive
actions to take. Nothing here touches any real system - it only mutates
the in-memory / SQLite simulated environment (block a simulated account,
revoke a simulated session, write an incident + audit log row).
"""

from dataclasses import dataclass, field
from typing import List

from agents.threat_analysis_agent import ThreatAssessment


@dataclass
class ResponseAction:
    actions: List[str] = field(default_factory=list)
    status: str = "MONITORED"   # MONITORED / ALERTED / BLOCKED


class ResponseAgent:
    name = "Response Agent"

    def decide(self, assessment: ThreatAssessment) -> ResponseAction:
        actions: List[str] = []

        if assessment.classification == "LOW":
            actions.append("No action - behaviour within normal range")
            status = "MONITORED"

        elif assessment.classification == "MEDIUM":
            actions.append("Flag session for continued monitoring")
            actions.append("Log event to audit trail")
            status = "MONITORED"

        elif assessment.classification == "HIGH":
            actions.append("Raise security alert")
            actions.append("Notify simulated administrator")
            actions.append("Require re-authentication (step-up auth) on next request")
            actions.append("Log event to audit trail")
            status = "ALERTED"

        else:  # CRITICAL
            actions.append("Block simulated account")
            actions.append("Revoke active simulated session")
            actions.append("Revoke temporary file permissions")
            actions.append("Notify simulated administrator")
            actions.append("Create security incident")
            actions.append("Log event to audit trail")
            status = "BLOCKED"

        return ResponseAction(actions=actions, status=status)
