"""Reputation tracking for MCP servers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServerReputation:
    server_url: str
    positive_reports: int = 0
    negative_reports: int = 0
    avg_trust_score: float = 0.0
    last_seen: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        total = self.positive_reports + self.negative_reports
        if total == 0:
            return 50.0
        ratio = self.positive_reports / total
        return round(ratio * 100.0, 1)


class ReputationTracker:
    """Tracks reputation scores for MCP servers over time."""

    def __init__(self) -> None:
        self._servers: dict[str, ServerReputation] = {}

    def record_attestation(
        self, server_url: str, trust_score: float, passed: bool
    ) -> None:
        rep = self._servers.get(server_url, ServerReputation(server_url=server_url))
        if passed:
            rep.positive_reports += 1
        else:
            rep.negative_reports += 1

        total = rep.positive_reports + rep.negative_reports
        rep.avg_trust_score = round(
            (rep.avg_trust_score * (total - 1) + trust_score) / total, 1
        )
        self._servers[server_url] = rep

    def get_reputation(self, server_url: str) -> ServerReputation | None:
        return self._servers.get(server_url)

    def get_score(self, server_url: str) -> float:
        rep = self._servers.get(server_url)
        return rep.score if rep else 50.0
