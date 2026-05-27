"""Policy evaluation for permission enforcement."""

from __future__ import annotations

from mcp_attest.models import PermissionRisk, ServerManifest


class PolicyEvaluator:
    """Evaluates whether a server manifest meets policy requirements."""

    def __init__(
        self,
        max_critical: int = 0,
        max_high: int = 2,
        allowed_permissions: set[str] | None = None,
    ) -> None:
        self.max_critical = max_critical
        self.max_high = max_high
        self.allowed_permissions = allowed_permissions

    def evaluate(self, manifest: ServerManifest) -> tuple[bool, list[str]]:
        violations: list[str] = []
        critical_count = 0
        high_count = 0

        for tool in manifest.tools:
            for perm in tool.permissions:
                risk = self._classify(perm)
                if risk == PermissionRisk.CRITICAL:
                    critical_count += 1
                elif risk == PermissionRisk.HIGH:
                    high_count += 1

                if (
                    self.allowed_permissions
                    and perm not in self.allowed_permissions
                ):
                    violations.append(
                        f"Tool '{tool.name}' has disallowed permission: {perm}"
                    )

        if critical_count > self.max_critical:
            violations.append(
                f"Too many critical permissions: {critical_count} "
                f"(max: {self.max_critical})"
            )
        if high_count > self.max_high:
            violations.append(
                f"Too many high permissions: {high_count} "
                f"(max: {self.max_high})"
            )

        return len(violations) == 0, violations

    @staticmethod
    def _classify(perm: str) -> PermissionRisk:
        critical = {
            "filesystem:delete",
            "network:raw",
            "process:execute",
            "secrets:write",
        }
        high = {
            "filesystem:write",
            "network:outbound",
            "process:spawn",
            "registry:write",
            "secrets:read",
        }
        if perm in critical:
            return PermissionRisk.CRITICAL
        if perm in high:
            return PermissionRisk.HIGH
        return PermissionRisk.LOW
