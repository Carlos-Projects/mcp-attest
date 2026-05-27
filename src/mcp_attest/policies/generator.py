"""Policy generation for MCPGuard integration."""

from __future__ import annotations

import json
from typing import Any

from mcp_attest.models import AttestationReport, TrustLevel


class PolicyGenerator:
    """Generates MCPGuard-compatible access policies from attestation reports."""

    def generate(self, report: AttestationReport) -> dict[str, Any]:
        trust = report.trust
        if not trust:
            return self._deny_all(report.server_url)

        if trust.revoked:
            return self._deny_all(report.server_url)

        if trust.level == TrustLevel.FULL:
            return self._full_access(report)
        if trust.level == TrustLevel.HIGH:
            return self._restricted_access(report)
        if trust.level == TrustLevel.MEDIUM:
            return self._limited_access(report)
        return self._deny_all(report.server_url)

    def _full_access(self, report: AttestationReport) -> dict[str, Any]:
        assert report.trust is not None
        return {
            "server": report.server_url,
            "action": "allow",
            "trust_score": report.trust.score,
            "restrictions": [],
            "audit_level": "minimal",
        }

    def _restricted_access(self, report: AttestationReport) -> dict[str, Any]:
        assert report.trust is not None
        restricted_tools: list[str] = []
        if report.permissions:
            for finding in report.permissions.findings:
                restricted_tools.append(finding.tool_name)

        return {
            "server": report.server_url,
            "action": "allow",
            "trust_score": report.trust.score,
            "restrictions": {
                "blocked_tools": list(set(restricted_tools)),
                "require_approval": True,
            },
            "audit_level": "standard",
        }

    def _limited_access(self, report: AttestationReport) -> dict[str, Any]:
        assert report.trust is not None
        return {
            "server": report.server_url,
            "action": "allow",
            "trust_score": report.trust.score,
            "restrictions": {
                "read_only": True,
                "require_approval": True,
                "session_timeout": 300,
            },
            "audit_level": "strict",
        }

    @staticmethod
    def _deny_all(server_url: str) -> dict[str, Any]:
        return {
            "server": server_url,
            "action": "deny",
            "trust_score": 0.0,
            "restrictions": {"all_blocked": True},
            "audit_level": "strict",
        }

    @staticmethod
    def generate_json(report: AttestationReport) -> str:
        gen = PolicyGenerator()
        policy = gen.generate(report)
        return json.dumps(policy, indent=2)
