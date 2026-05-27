"""SARIF reporter for integration with security tooling."""

from __future__ import annotations

import json
from typing import Any

from mcp_attest.models import AttestationReport, IntegrityStatus, TrustLevel


class SarifReporter:
    """Formats attestation reports as SARIF format."""

    @staticmethod
    def render(report: AttestationReport) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-attest",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/Carlos-Projects/mcp-attest",
                        }
                    },
                    "results": SarifReporter._build_results(report),
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    @staticmethod
    def _build_results(report: AttestationReport) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        if report.identity and not report.identity.verified:
            results.append(
                {
                    "ruleId": "MCP-IDENTITY-001",
                    "level": "error",
                    "message": {
                        "text": f"Identity verification failed for {report.server_url}"
                    },
                }
            )

        if report.integrity and report.integrity.status == IntegrityStatus.MODIFIED:
            results.append(
                {
                    "ruleId": "MCP-INTEGRITY-001",
                    "level": "warning",
                    "message": {
                        "text": (
                            f"Server manifest modified: "
                            f"{len(report.integrity.changed_tools)} changed, "
                            f"{len(report.integrity.added_tools)} added, "
                            f"{len(report.integrity.removed_tools)} removed"
                        )
                    },
                }
            )

        if report.permissions and not report.permissions.compliant:
            for finding in report.permissions.findings:
                results.append(
                    {
                        "ruleId": "MCP-PERMISSION-001",
                        "level": "warning",
                    "message": {
                        "text": (
                            f"Tool '{finding.tool_name}' has "
                            f"{finding.risk.value} permission: "
                            f"{finding.declared_permission}"
                        )
                    },
                    }
                )

        if report.trust and report.trust.level in (
            TrustLevel.UNTRUSTED,
            TrustLevel.LOW,
        ):
            results.append(
                {
                    "ruleId": "MCP-TRUST-001",
                    "level": "error",
                    "message": {
                        "text": f"Low trust score: {report.trust.score:.1f}/100 "
                        f"({report.trust.level.value})"
                    },
                }
            )

        if not results:
            results.append(
                {
                    "ruleId": "MCP-PASS-001",
                    "level": "none",
                    "message": {
                        "text": f"All attestation checks passed for {report.server_url}"
                    },
                }
            )

        return results
