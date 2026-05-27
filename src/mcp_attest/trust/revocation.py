"""Revocation list checking for MCP servers."""

from __future__ import annotations

import json
from pathlib import Path


class RevocationChecker:
    """Checks if an MCP server URL or fingerprint is on a revocation list."""

    def __init__(self, revoked_entries: list[str] | None = None) -> None:
        self._revoked: set[str] = set(revoked_entries or [])

    def is_revoked(self, server_url: str) -> bool:
        return server_url in self._revoked

    def is_fingerprint_revoked(self, fingerprint: str) -> bool:
        return fingerprint in self._revoked

    def add(self, entry: str) -> None:
        self._revoked.add(entry)

    def remove(self, entry: str) -> None:
        self._revoked.discard(entry)

    def load_from_file(self, path: str | Path) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        with open(p) as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else data.get("revoked", [])
        self._revoked.update(entries)
        return len(self._revoked)

    def save_to_file(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            json.dump({"revoked": sorted(self._revoked)}, f, indent=2)

    @property
    def count(self) -> int:
        return len(self._revoked)

    @property
    def entries(self) -> list[str]:
        return sorted(self._revoked)
