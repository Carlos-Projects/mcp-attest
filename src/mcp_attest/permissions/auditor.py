"""Permission auditing for MCP server tools."""

from __future__ import annotations

from typing import Any

from mcp_attest.models import (
    PermissionFinding,
    PermissionResult,
    PermissionRisk,
    ServerManifest,
    ToolDeclaration,
)
from mcp_attest.permissions.least_privilege import LeastPrivilegeChecker

# Default dangerous permissions map
DEFAULT_DANGEROUS_PERMISSIONS: dict[str, PermissionRisk] = {
    "filesystem:write": PermissionRisk.CRITICAL,
    "filesystem:delete": PermissionRisk.CRITICAL,
    "network:outbound": PermissionRisk.HIGH,
    "network:raw": PermissionRisk.CRITICAL,
    "process:execute": PermissionRisk.CRITICAL,
    "process:spawn": PermissionRisk.HIGH,
    "registry:write": PermissionRisk.HIGH,
    "secrets:read": PermissionRisk.HIGH,
    "secrets:write": PermissionRisk.CRITICAL,
}


class PermissionAuditor:
    """Audits tool permissions against declared policies and least privilege.

    Args:
        custom_permissions: Optional dict mapping permission strings to
            PermissionRisk values. Merged with defaults (custom overrides).
    """

    def __init__(
        self,
        custom_permissions: dict[str, Any] | None = None,
    ) -> None:
        self.dangerous: dict[str, PermissionRisk] = dict(DEFAULT_DANGEROUS_PERMISSIONS)
        if custom_permissions:
            for perm, risk in custom_permissions.items():
                if isinstance(risk, str):
                    risk = PermissionRisk(risk)
                self.dangerous[perm] = risk

    async def audit(self, manifest: ServerManifest) -> PermissionResult:
        findings: list[PermissionFinding] = []

        for tool in manifest.tools:
            tool_findings = self._audit_tool(tool)
            findings.extend(tool_findings)

        lp_score = LeastPrivilegeChecker.score(manifest)
        compliant = len(findings) == 0

        return PermissionResult(
            compliant=compliant,
            findings=findings,
            least_privilege_score=lp_score,
        )

    def _audit_tool(self, tool: ToolDeclaration) -> list[PermissionFinding]:
        findings = []
        for perm in tool.permissions:
            risk = self._assess_permission(perm)
            if risk in (PermissionRisk.HIGH, PermissionRisk.CRITICAL):
                findings.append(
                    PermissionFinding(
                        tool_name=tool.name,
                        declared_permission=perm,
                        actual_permission=perm,
                        risk=risk,
                        recommendation=self._recommendation(perm),
                    )
                )
        return findings

    def _assess_permission(self, perm: str) -> PermissionRisk:
        return self.dangerous.get(perm, PermissionRisk.LOW)

    @staticmethod
    def _recommendation(perm: str) -> str:
        recommendations = {
            "filesystem:write": "Restrict to specific directories only",
            "filesystem:delete": "Remove delete permission if not required",
            "network:outbound": "Restrict to allowlisted domains",
            "network:raw": "Remove raw network access",
            "process:execute": "Remove process execution capability",
            "process:spawn": "Restrict to specific allowed processes",
            "registry:write": "Remove registry write access",
            "secrets:read": "Use secret scoping to limit access",
            "secrets:write": "Remove secret write capability",
        }
        return recommendations.get(perm, "Review and minimize permission")
