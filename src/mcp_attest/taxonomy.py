"""Taxonomy integration for MCP Attest findings."""

from __future__ import annotations

from typing import Any

from mcp_attest.models import (
    AttestationReport,
    IntegrityStatus,
    PermissionFinding,
    PermissionRisk,
    TrustLevel,
)


def attestation_to_taxonomy_events(
    report: AttestationReport,
) -> list[dict[str, Any]]:
    """Convert an attestation report into mcp-taxonomy events."""
    events: list[dict[str, Any]] = []
    ts = report.timestamp.isoformat()

    if report.identity and not report.identity.verified:
        events.append(
            {
                "source": "mcp-attest",
                "attack_category": "MISCONFIGURATION",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "Identity verification failed",
                "description": (
                    f"Server {report.server_url} failed identity verification"
                ),
                "recommendation": (
                    "Verify TLS certificate or signature before connecting"
                ),
                "detection_method": "ATTESTATION_CHECK",
                "target": report.server_url,
                "timestamp": ts,
                "blocked": True,
                "risk_score": 75,
            }
        )

    if report.integrity and report.integrity.status == IntegrityStatus.MODIFIED:
        events.append(
            {
                "source": "mcp-attest",
                "attack_category": "TOOL_POISONING",
                "severity": "CRITICAL",
                "confidence": "MEDIUM",
                "title": "Server manifest modified",
                "description": (
                    f"Manifest changed: {len(report.integrity.added_tools)} added, "
                    f"{len(report.integrity.removed_tools)} removed, "
                    f"{len(report.integrity.changed_tools)} modified"
                ),
                "recommendation": "Review changes before trusting server",
                "detection_method": "ATTESTATION_CHECK",
                "target": report.server_url,
                "timestamp": ts,
                "blocked": True,
                "risk_score": 90,
            }
        )

    if report.permissions:
        for finding in report.permissions.findings:
            events.append(_permission_finding_to_event(finding, report.server_url, ts))

    if report.trust and report.trust.revoked:
        events.append(
            {
                "source": "mcp-attest",
                "attack_category": "POLICY_VIOLATION",
                "severity": "CRITICAL",
                "confidence": "CERTAIN",
                "title": "Server is revoked",
                "description": f"Server {report.server_url} is on the revocation list",
                "recommendation": "Do not connect to this server",
                "detection_method": "ATTESTATION_CHECK",
                "target": report.server_url,
                "timestamp": ts,
                "blocked": True,
                "risk_score": 100,
            }
        )

    if report.trust and report.trust.level in (
        TrustLevel.UNTRUSTED,
        TrustLevel.LOW,
    ):
        events.append(
            {
                "source": "mcp-attest",
                "attack_category": "MISCONFIGURATION",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "title": f"Low trust score: {report.trust.score:.1f}",
                "description": f"Server {report.server_url} has low trust",
                "recommendation": "Review server configuration",
                "detection_method": "ATTESTATION_CHECK",
                "target": report.server_url,
                "timestamp": ts,
                "blocked": report.trust.score < 25,
                "risk_score": int(100 - report.trust.score),
            }
        )

    return events


def _permission_finding_to_event(
    finding: PermissionFinding, server_url: str, timestamp: str
) -> dict[str, Any]:
    severity_map = {
        PermissionRisk.LOW: "LOW",
        PermissionRisk.MEDIUM: "MEDIUM",
        PermissionRisk.HIGH: "HIGH",
        PermissionRisk.CRITICAL: "CRITICAL",
    }
    return {
        "source": "mcp-attest",
        "attack_category": "POLICY_VIOLATION",
        "severity": severity_map.get(finding.risk, "MEDIUM"),
        "confidence": "HIGH",
        "title": f"Excessive permission: {finding.declared_permission}",
        "description": (
            f"Tool '{finding.tool_name}' has {finding.risk.value} permission"
        ),
        "recommendation": finding.recommendation,
        "detection_method": "ATTESTATION_CHECK",
        "target": f"{server_url}#{finding.tool_name}",
        "timestamp": timestamp,
        "blocked": finding.risk in (PermissionRisk.HIGH, PermissionRisk.CRITICAL),
        "risk_score": {
            PermissionRisk.LOW: 20,
            PermissionRisk.MEDIUM: 50,
            PermissionRisk.HIGH: 75,
            PermissionRisk.CRITICAL: 95,
        }.get(finding.risk, 50),
    }
