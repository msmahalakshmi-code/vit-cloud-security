"""
AGENT 2 - DATA ACCESS AGENT
----------------------------
Watches a user's rolling file-access behaviour: how many files viewed,
how many downloaded, and whether any access to a resource they are not
permitted to touch (role-based policy violation) occurred.
"""

from dataclasses import dataclass, field
from typing import List

from agents.authentication_agent import AgentObservation


class DataAccessAgent:
    name = "Data Access Agent"

    WEIGHT_FILES_ACCESSED_PER_10 = 5     # every 10 files accessed above baseline
    MAX_FILE_ACCESS_SCORE = 30
    WEIGHT_DOWNLOADS_PER_5 = 6
    MAX_DOWNLOAD_SCORE = 30
    WEIGHT_UNAUTHORIZED_ATTEMPT = 25
    WEIGHT_SENSITIVE_ACCESS = 20

    NORMAL_FILES_ACCESSED = 10   # a normal session touches ~5-10 files
    NORMAL_DOWNLOADS = 3

    def evaluate(self, user_stats: dict) -> AgentObservation:
        """
        user_stats example:
        {
            "files_accessed": 132,
            "downloads": 87,
            "unauthorized_attempts": 1,
            "sensitive_files_touched": 1,
        }
        """
        score = 0
        reasons = []

        files = user_stats.get("files_accessed", 0)
        if files > self.NORMAL_FILES_ACCESSED:
            excess = files - self.NORMAL_FILES_ACCESSED
            file_score = min((excess / 10) * self.WEIGHT_FILES_ACCESSED_PER_10,
                              self.MAX_FILE_ACCESS_SCORE)
            score += file_score
            if files >= 30:
                reasons.append(f"{files} files accessed in current window (baseline ~{self.NORMAL_FILES_ACCESSED})")

        downloads = user_stats.get("downloads", 0)
        if downloads > self.NORMAL_DOWNLOADS:
            excess = downloads - self.NORMAL_DOWNLOADS
            dl_score = min((excess / 5) * self.WEIGHT_DOWNLOADS_PER_5,
                            self.MAX_DOWNLOAD_SCORE)
            score += dl_score
            if downloads >= 10:
                reasons.append(f"{downloads} downloads in current window (baseline ~{self.NORMAL_DOWNLOADS})")

        unauthorized = user_stats.get("unauthorized_attempts", 0)
        if unauthorized > 0:
            score += self.WEIGHT_UNAUTHORIZED_ATTEMPT
            reasons.append(f"{unauthorized} attempt(s) to access resources outside role permissions")

        if user_stats.get("sensitive_files_touched", 0) > 0:
            score += self.WEIGHT_SENSITIVE_ACCESS
            reasons.append("Access to a sensitive/classified resource (e.g. exam paper, private record)")

        score = min(int(round(score)), 100)
        level = "LOW" if score < 31 else "MEDIUM" if score < 61 else "HIGH"

        return AgentObservation(agent=self.name, risk_score=score, level=level, reasons=reasons)
