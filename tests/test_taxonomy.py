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
from mcp_attest.taxonomy import attestation_to_taxonomy_events


class TestTaxonomyIntegration:
    def test_empty_report_produces_no_events(self):
        report = AttestationReport(server_url="https://test.com")
        events = attestation_to_taxonomy_events(report)
        assert events == []

    def test_identity_failure_produces_event(self):
        report = AttestationReport(
            server_url="https://test.com",
            identity=IdentityResult(
                verified=False, method=IdentityMethod.TLS_CERT, subject="test"
            ),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 1
        assert events[0]["source"] == "mcp-attest"
        assert events[0]["attack_category"] == "MISCONFIGURATION"
        assert events[0]["severity"] == "HIGH"
        assert events[0]["blocked"] is True
        assert events[0]["risk_score"] == 75

    def test_integrity_modified_produces_event(self):
        report = AttestationReport(
            server_url="https://test.com",
            integrity=IntegrityResult(
                status=IntegrityStatus.MODIFIED,
                manifest_hash="h",
                fingerprint="f",
                added_tools=["new"],
                removed_tools=["old"],
                changed_tools=["mod"],
            ),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 1
        assert events[0]["attack_category"] == "TOOL_POISONING"
        assert events[0]["severity"] == "CRITICAL"
        assert events[0]["risk_score"] == 90

    def test_permission_findings_produce_events(self):
        report = AttestationReport(
            server_url="https://test.com",
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="exec",
                        declared_permission="process:execute",
                        actual_permission="process:execute",
                        risk=PermissionRisk.CRITICAL,
                        recommendation="Remove",
                    ),
                    PermissionFinding(
                        tool_name="read",
                        declared_permission="filesystem:read",
                        actual_permission="filesystem:read",
                        risk=PermissionRisk.LOW,
                        recommendation="Review",
                    ),
                ],
            ),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 2
        assert events[0]["severity"] == "CRITICAL"
        assert events[0]["blocked"] is True
        assert events[1]["severity"] == "LOW"
        assert events[1]["blocked"] is False

    def test_revoked_server_produces_event(self):
        report = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=0.0, level=TrustLevel.UNTRUSTED, revoked=True),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 2
        assert events[0]["attack_category"] == "POLICY_VIOLATION"
        assert events[0]["risk_score"] == 100

    def test_low_trust_produces_event(self):
        report = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=15.0, level=TrustLevel.UNTRUSTED),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 1
        assert events[0]["severity"] == "MEDIUM"
        assert events[0]["blocked"] is True

    def test_medium_trust_produces_event(self):
        report = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=40.0, level=TrustLevel.LOW),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 1
        assert events[0]["blocked"] is False

    def test_full_report_multiple_events(self):
        report = AttestationReport(
            server_url="https://test.com",
            identity=IdentityResult(
                verified=False, method=IdentityMethod.TLS_CERT, subject="test"
            ),
            integrity=IntegrityResult(
                status=IntegrityStatus.MODIFIED,
                manifest_hash="h",
                fingerprint="f",
                added_tools=["x"],
            ),
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="bad",
                        declared_permission="process:execute",
                        actual_permission="process:execute",
                        risk=PermissionRisk.CRITICAL,
                        recommendation="Remove",
                    )
                ],
            ),
            trust=TrustResult(score=10.0, level=TrustLevel.UNTRUSTED, revoked=True),
        )
        events = attestation_to_taxonomy_events(report)
        assert len(events) == 5
        assert all(e["source"] == "mcp-attest" for e in events)

    def test_event_timestamp_present(self):
        report = AttestationReport(
            server_url="https://test.com",
            identity=IdentityResult(
                verified=False, method=IdentityMethod.TLS_CERT, subject="t"
            ),
        )
        events = attestation_to_taxonomy_events(report)
        assert "timestamp" in events[0]
        assert len(events[0]["timestamp"]) > 0

    def test_medium_risk_permission(self):
        report = AttestationReport(
            server_url="https://test.com",
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="t",
                        declared_permission="p",
                        actual_permission="p",
                        risk=PermissionRisk.MEDIUM,
                        recommendation="Review",
                    )
                ],
            ),
        )
        events = attestation_to_taxonomy_events(report)
        assert events[0]["severity"] == "MEDIUM"
        assert events[0]["risk_score"] == 50

    def test_high_risk_permission(self):
        report = AttestationReport(
            server_url="https://test.com",
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="t",
                        declared_permission="p",
                        actual_permission="p",
                        risk=PermissionRisk.HIGH,
                        recommendation="Restrict",
                    )
                ],
            ),
        )
        events = attestation_to_taxonomy_events(report)
        assert events[0]["severity"] == "HIGH"
        assert events[0]["blocked"] is True
        assert events[0]["risk_score"] == 75
