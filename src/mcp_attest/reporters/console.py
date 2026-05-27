"""Console reporter using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from mcp_attest.models import AttestationReport, IntegrityStatus, TrustLevel


class ConsoleReporter:
    """Formats attestation reports for terminal display."""

    def __init__(self) -> None:
        self.console = Console()

    def render(self, report: AttestationReport) -> None:
        self.console.print(
            Panel(
                f"MCP Attestation Report: {report.server_url}",
                subtitle=str(report.timestamp),
                border_style=self._trust_color(report),
            )
        )

        if report.identity:
            self._render_identity(report)
        if report.integrity:
            self._render_integrity(report)
        if report.permissions:
            self._render_permissions(report)
        if report.trust:
            self._render_trust(report)

        self.console.print(f"\nPolicy: [bold]{report.policy_recommended}[/]")

    def _render_identity(self, report: AttestationReport) -> None:
        identity = report.identity
        assert identity is not None
        status = "[green]VERIFIED[/]" if identity.verified else "[red]FAILED[/]"
        self.console.print(f"\n  Identity: {status}")
        self.console.print(f"  Method: {identity.method}")
        self.console.print(f"  Subject: {identity.subject}")

    def _render_integrity(self, report: AttestationReport) -> None:
        integrity = report.integrity
        assert integrity is not None
        status_map = {
            IntegrityStatus.VERIFIED: "[green]VERIFIED[/]",
            IntegrityStatus.MODIFIED: "[yellow]MODIFIED[/]",
            IntegrityStatus.UNKNOWN: "[gray]UNKNOWN[/]",
        }
        status = status_map.get(integrity.status, "[gray]UNKNOWN[/]")
        self.console.print(f"\n  Integrity: {status}")
        self.console.print(f"  Hash: {integrity.manifest_hash[:16]}...")
        self.console.print(f"  Fingerprint: {integrity.fingerprint[:16]}...")

        if integrity.added_tools:
            self.console.print(f"  Added: {', '.join(integrity.added_tools)}")
        if integrity.removed_tools:
            self.console.print(f"  Removed: {', '.join(integrity.removed_tools)}")

    def _render_permissions(self, report: AttestationReport) -> None:
        perms = report.permissions
        assert perms is not None
        status = "[green]COMPLIANT[/]" if perms.compliant else "[red]FINDINGS[/]"
        self.console.print(f"\n  Permissions: {status}")
        self.console.print(
            f"  Least Privilege Score: {perms.least_privilege_score:.1f}"
        )
        for finding in perms.findings:
            self.console.print(
                f"    - [{finding.risk.value}] {finding.tool_name}: "
                f"{finding.declared_permission}"
            )

    def _render_trust(self, report: AttestationReport) -> None:
        trust = report.trust
        assert trust is not None
        level_color = {
            TrustLevel.FULL: "green",
            TrustLevel.HIGH: "blue",
            TrustLevel.MEDIUM: "yellow",
            TrustLevel.LOW: "orange",
            TrustLevel.UNTRUSTED: "red",
        }
        color = level_color.get(trust.level, "white")
        self.console.print(f"\n  Trust Score: [{color}]{trust.score:.1f}/100[/]")
        self.console.print(f"  Level: [{color}]{trust.level.value}[/]")
        if trust.revoked:
            self.console.print("  [red]REVOKED[/]")

    @staticmethod
    def _trust_color(report: AttestationReport) -> str:
        if not report.trust:
            return "white"
        level = report.trust.level
        if level in (TrustLevel.FULL, TrustLevel.HIGH):
            return "green"
        if level == TrustLevel.MEDIUM:
            return "yellow"
        return "red"
