"""Reputation tracking for MCP servers with optional SQLite persistence."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


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
    """Tracks reputation scores for MCP servers over time.

    Args:
        db_path: Optional path to a SQLite database for persistence.
            If None, reputation is kept in memory only.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._servers: dict[str, ServerReputation] = {}
        self._db_path = db_path
        if db_path:
            self._init_db()
            self._load()

    def _init_db(self) -> None:
        assert self._db_path is not None
        path = Path(self._db_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS reputation (
                server_url TEXT PRIMARY KEY,
                positive_reports INTEGER DEFAULT 0,
                negative_reports INTEGER DEFAULT 0,
                avg_trust_score REAL DEFAULT 0.0,
                last_seen TEXT DEFAULT '',
                tags TEXT DEFAULT '[]'
            )"""
        )
        self._conn.commit()

    def _load(self) -> None:
        cursor = self._conn.execute("SELECT * FROM reputation")
        for row in cursor.fetchall():
            self._servers[row[0]] = ServerReputation(
                server_url=row[0],
                positive_reports=row[1],
                negative_reports=row[2],
                avg_trust_score=row[3],
                last_seen=row[4],
                tags=json.loads(row[5]),
            )

    def _save(self, server_url: str) -> None:
        if not self._db_path:
            return
        rep = self._servers[server_url]
        self._conn.execute(
            """INSERT OR REPLACE INTO reputation
               (server_url, positive_reports, negative_reports,
                avg_trust_score, last_seen, tags)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                rep.server_url,
                rep.positive_reports,
                rep.negative_reports,
                rep.avg_trust_score,
                rep.last_seen,
                json.dumps(rep.tags),
            ),
        )
        self._conn.commit()

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
        rep.last_seen = datetime.now(UTC).isoformat()
        self._servers[server_url] = rep
        self._save(server_url)

    def get_reputation(self, server_url: str) -> ServerReputation | None:
        return self._servers.get(server_url)

    def get_score(self, server_url: str) -> float:
        rep = self._servers.get(server_url)
        return rep.score if rep else 50.0

    def close(self) -> None:
        if hasattr(self, "_conn"):
            self._conn.close()
