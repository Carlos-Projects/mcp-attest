import pytest

from mcp_attest.models import (
    AttestationReport,
    IdentityMethod,
    IdentityResult,
    IntegrityResult,
    IntegrityStatus,
    PermissionFinding,
    PermissionResult,
    PermissionRisk,
    TrustLevel,
    TrustResult,
)
from mcp_attest.reporters.console import ConsoleReporter
from mcp_attest.reporters.json import JsonReporter
from mcp_attest.reporters.sarif import SarifReporter


@pytest.fixture
def sample_report():
    return AttestationReport(
        server_url="https://test.com",
        identity=IdentityResult(
            verified=True, method=IdentityMethod.TLS_CERT, subject="CN=test"
        ),
        integrity=IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="abc123",
            fingerprint="fp456",
        ),
        permissions=PermissionResult(compliant=True),
        trust=TrustResult(score=85.0, level=TrustLevel.HIGH),
    )


@pytest.fixture
def failed_report():
    return AttestationReport(
        server_url="https://bad.com",
        identity=IdentityResult(
            verified=False, method=IdentityMethod.TLS_CERT, subject="bad"
        ),
        integrity=IntegrityResult(
            status=IntegrityStatus.MODIFIED,
            manifest_hash="xyz",
            fingerprint="fp",
            added_tools=["new_tool"],
            removed_tools=["old_tool"],
        ),
        permissions=PermissionResult(compliant=False, least_privilege_score=40.0),
        trust=TrustResult(score=15.0, level=TrustLevel.UNTRUSTED),
    )


class TestConsoleReporter:
    def test_render_does_not_crash(self, sample_report, capsys):
        reporter = ConsoleReporter()
        reporter.render(sample_report)
        captured = capsys.readouterr()
        assert "test.com" in captured.out

    def test_render_failed_report(self, failed_report, capsys):
        reporter = ConsoleReporter()
        reporter.render(failed_report)
        captured = capsys.readouterr()
        assert "bad.com" in captured.out

    def test_trust_color_full(self):
        report = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=95.0, level=TrustLevel.FULL),
        )
        color = ConsoleReporter._trust_color(report)
        assert color == "green"

    def test_trust_color_medium(self):
        report = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=55.0, level=TrustLevel.MEDIUM),
        )
        color = ConsoleReporter._trust_color(report)
        assert color == "yellow"

    def test_trust_color_untrusted(self):
        report = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=10.0, level=TrustLevel.UNTRUSTED),
        )
        color = ConsoleReporter._trust_color(report)
        assert color == "red"

    def test_trust_color_no_trust(self):
        report = AttestationReport(server_url="https://test.com")
        color = ConsoleReporter._trust_color(report)
        assert color == "white"


class TestJsonReporter:
    def test_render(self, sample_report):
        output = JsonReporter.render(sample_report)
        assert isinstance(output, str)
        assert "test.com" in output

    def test_render_batch(self, sample_report):
        output = JsonReporter.render_batch([sample_report])
        assert '"count": 1' in output
        assert '"version": "1.0"' in output

    def test_parse_roundtrip(self, sample_report):
        json_str = JsonReporter.render(sample_report)
        parsed = JsonReporter.parse(json_str)
        assert parsed.server_url == sample_report.server_url

    def test_render_empty_batch(self):
        output = JsonReporter.render_batch([])
        assert '"count": 0' in output


class TestSarifReporter:
    def test_render_pass(self, sample_report):
        output = SarifReporter.render(sample_report)
        assert isinstance(output, str)
        assert "mcp-attest" in output
        assert "2.1.0" in output

    def test_render_identity_failure(self):
        report = AttestationReport(
            server_url="https://bad.com",
            identity=IdentityResult(
                verified=False, method=IdentityMethod.TLS_CERT, subject="bad"
            ),
        )
        output = SarifReporter.render(report)
        assert "MCP-IDENTITY-001" in output

    def test_render_integrity_modified(self):
        report = AttestationReport(
            server_url="https://bad.com",
            integrity=IntegrityResult(
                status=IntegrityStatus.MODIFIED,
                manifest_hash="h",
                fingerprint="f",
                changed_tools=["t1"],
                added_tools=["t2"],
                removed_tools=["t3"],
            ),
        )
        output = SarifReporter.render(report)
        assert "MCP-INTEGRITY-001" in output

    def test_render_permission_findings(self):
        from mcp_attest.models import PermissionFinding, PermissionRisk

        report = AttestationReport(
            server_url="https://bad.com",
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="exec",
                        declared_permission="process:execute",
                        actual_permission="process:execute",
                        risk=PermissionRisk.CRITICAL,
                        recommendation="Remove",
                    )
                ],
            ),
        )
        output = SarifReporter.render(report)
        assert "MCP-PERMISSION-001" in output

    def test_render_low_trust(self):
        report = AttestationReport(
            server_url="https://bad.com",
            trust=TrustResult(score=10.0, level=TrustLevel.UNTRUSTED),
        )
        output = SarifReporter.render(report)
        assert "MCP-TRUST-001" in output

    def test_render_schema_present(self, sample_report):
        output = SarifReporter.render(sample_report)
        assert "$schema" in output


class TestConsoleReporterEdgeCases:
    def test_render_revoked_with_findings(self, capsys):
        report = AttestationReport(
            server_url="https://revoked.com",
            identity=IdentityResult(
                verified=True, method=IdentityMethod.TLS_CERT, subject="t"
            ),
            integrity=IntegrityResult(
                status=IntegrityStatus.VERIFIED,
                manifest_hash="h",
                fingerprint="f",
            ),
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="exec",
                        declared_permission="process:execute",
                        actual_permission="process:execute",
                        risk=PermissionRisk.CRITICAL,
                        recommendation="Remove",
                    )
                ],
            ),
            trust=TrustResult(score=0.0, level=TrustLevel.UNTRUSTED, revoked=True),
        )
        reporter = ConsoleReporter()
        reporter.render(report)
        captured = capsys.readouterr()
        assert "REVOKED" in captured.out
        assert "FINDINGS" in captured.out
        assert "process:execute" in captured.out

    def test_render_identity_and_integrity_only(self, capsys):
        report = AttestationReport(
            server_url="https://test.com",
            identity=IdentityResult(
                verified=True, method=IdentityMethod.TLS_CERT, subject="t"
            ),
            integrity=IntegrityResult(
                status=IntegrityStatus.VERIFIED,
                manifest_hash="abc123",
                fingerprint="fp456",
            ),
        )
        reporter = ConsoleReporter()
        reporter.render(report)
        captured = capsys.readouterr()
        assert "VERIFIED" in captured.out
