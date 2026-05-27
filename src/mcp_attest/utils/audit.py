"""Audit logging for attestation decisions.

Writes JSONL (JSON Lines) files with one attestation event per line,
enabling replay, forensics, and SIEM integration.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_attest.models import AttestationReport


class AuditLogger:
    """Logs attestation decisions to a JSONL audit trail.

    Args:
        log_path: Path to the JSONL log file. If None, logging is disabled.
    """

    def __init__(self, log_path: str | None = None) -> None:
        self.log_path = log_path

    def log_attestation(self, report: AttestationReport) -> None:
        """Record an attestation decision to the audit log."""
        if not self.log_path:
            return

        entry = self._build_entry(report)
        path = Path(self.log_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def _build_entry(self, report: AttestationReport) -> dict[str, Any]:
        identity = report.identity
        integrity = report.integrity
        permissions = report.permissions
        trust = report.trust

        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "server_url": report.server_url,
            "identity": {
                "verified": identity.verified if identity else None,
                "method": identity.method.value if identity else None,
                "subject": identity.subject if identity else None,
                "issuer": identity.issuer if identity else None,
            },
            "integrity": {
                "status": integrity.status.value if integrity else None,
                "manifest_hash": integrity.manifest_hash if integrity else None,
                "fingerprint": integrity.fingerprint if integrity else None,
            },
            "permissions": {
                "least_privilege_score": (
                    permissions.least_privilege_score if permissions else None
                ),
                "finding_count": len(permissions.findings) if permissions else 0,
            },
            "trust": {
                "score": trust.score if trust else None,
                "level": trust.level.value if trust else None,
                "revoked": trust.revoked if trust else None,
            },
            "policy_recommended": report.policy_recommended,
        }
