"""
AGENT 1 - AUTHENTICATION / LOGIN AGENT
----------------------------------------
Watches a user's rolling login behaviour (failed attempts, new device,
unusual login hour, new IP) inside the current time window and produces
a risk observation. This agent does NOT decide what to do about it -
it only reports evidence to the Threat Analysis Agent.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class AgentObservation:
    agent: str
    risk_score: int          # 0-100, this agent's own contribution
    level: str                # LOW / MEDIUM / HIGH
    reasons: List[str] = field(default_factory=list)


class AuthenticationAgent:
    name = "Authentication Agent"

    # --- tunable rule weights -------------------------------------------
    WEIGHT_FAILED_LOGIN_PER_ATTEMPT = 1.5   # capped below
    MAX_FAILED_LOGIN_SCORE = 35
    WEIGHT_NEW_DEVICE = 15
    WEIGHT_NEW_IP = 10
    WEIGHT_UNUSUAL_HOUR = 10
    WEIGHT_SUCCESS_AFTER_MANY_FAILS = 20

    UNUSUAL_HOURS = set(range(0, 5))  # 12am - 5am considered unusual for a student

    def evaluate(self, user_stats: dict) -> AgentObservation:
        """
        user_stats is the rolling window snapshot maintained by the engine, e.g.:
        {
            "failed_logins": 47,
            "successful_logins": 1,
            "new_device": True,
            "new_ip": True,
            "last_login_hour": 2,
        }
        """
        score = 0
        reasons = []

        failed = user_stats.get("failed_logins", 0)
        if failed > 0:
            failed_score = min(failed * self.WEIGHT_FAILED_LOGIN_PER_ATTEMPT,
                                self.MAX_FAILED_LOGIN_SCORE)
            score += failed_score
            if failed >= 5:
                reasons.append(f"{failed} failed login attempts in current window")

        if user_stats.get("new_device"):
            score += self.WEIGHT_NEW_DEVICE
            reasons.append("Login from a previously unseen device")

        if user_stats.get("new_ip"):
            score += self.WEIGHT_NEW_IP
            reasons.append("Login from a previously unseen IP / location")

        hour = user_stats.get("last_login_hour")
        if hour is not None and hour in self.UNUSUAL_HOURS:
            score += self.WEIGHT_UNUSUAL_HOUR
            reasons.append(f"Login at unusual hour ({hour}:00)")

        if failed >= 5 and user_stats.get("successful_logins", 0) >= 1:
            score += self.WEIGHT_SUCCESS_AFTER_MANY_FAILS
            reasons.append("Successful login immediately after repeated failures "
                            "(possible brute-force / credential stuffing)")

        score = min(int(round(score)), 100)
        level = "LOW" if score < 31 else "MEDIUM" if score < 61 else "HIGH"

        return AgentObservation(agent=self.name, risk_score=score, level=level, reasons=reasons)
