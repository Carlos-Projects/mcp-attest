"""Least privilege scoring for MCP server tools."""

from __future__ import annotations

from mcp_attest.models import ServerManifest


class LeastPrivilegeChecker:
    """Scores how well a server adheres to least privilege principle."""

    PERMISSION_SEVERITY = {
        "filesystem:write": 3,
        "filesystem:delete": 5,
        "network:outbound": 2,
        "network:raw": 5,
        "process:execute": 5,
        "process:spawn": 3,
        "registry:write": 4,
        "secrets:read": 3,
        "secrets:write": 5,
    }

    @staticmethod
    def score(manifest: ServerManifest) -> float:
        if not manifest.tools:
            return 100.0

        total_severity = 0.0
        tool_count = len(manifest.tools)

        for tool in manifest.tools:
            for perm in tool.permissions:
                severity = LeastPrivilegeChecker.PERMISSION_SEVERITY.get(perm, 1)
                total_severity += severity

        max_possible = tool_count * 10
        if max_possible == 0:
            return 100.0  # pragma: no cover

        ratio = total_severity / max_possible
        return max(0.0, 100.0 * (1.0 - ratio))

    @staticmethod
    def has_excessive_permissions(
        manifest: ServerManifest, threshold: float = 50.0
    ) -> bool:
        return LeastPrivilegeChecker.score(manifest) < threshold
