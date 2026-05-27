import pytest

from mcp_attest.models import (
    AttestationReport,
    TrustLevel,
    TrustResult,
)
from mcp_attest.policies.generator import PolicyGenerator


@pytest.fixture
def generator():
    return PolicyGenerator()


@pytest.fixture
def full_trust_report():
    return AttestationReport(
        server_url="https://trusted.com",
        trust=TrustResult(score=95.0, level=TrustLevel.FULL),
    )


@pytest.fixture
def high_trust_report():
    return AttestationReport(
        server_url="https://good.com",
        trust=TrustResult(score=80.0, level=TrustLevel.HIGH),
    )


@pytest.fixture
def medium_trust_report():
    return AttestationReport(
        server_url="https://ok.com",
        trust=TrustResult(score=60.0, level=TrustLevel.MEDIUM),
    )


@pytest.fixture
def low_trust_report():
    return AttestationReport(
        server_url="https://bad.com",
        trust=TrustResult(score=20.0, level=TrustLevel.LOW),
    )


@pytest.fixture
def revoked_report():
    return AttestationReport(
        server_url="https://revoked.com",
        trust=TrustResult(score=0.0, level=TrustLevel.UNTRUSTED, revoked=True),
    )


class TestPolicyGenerator:
    def test_full_access(self, generator, full_trust_report):
        policy = generator.generate(full_trust_report)
        assert policy["action"] == "allow"
        assert policy["restrictions"] == []
        assert policy["audit_level"] == "minimal"

    def test_restricted_access(self, generator, high_trust_report):
        policy = generator.generate(high_trust_report)
        assert policy["action"] == "allow"
        assert "require_approval" in policy["restrictions"]
        assert policy["audit_level"] == "standard"

    def test_limited_access(self, generator, medium_trust_report):
        policy = generator.generate(medium_trust_report)
        assert policy["action"] == "allow"
        assert policy["restrictions"]["read_only"] is True
        assert policy["audit_level"] == "strict"

    def test_deny_low_trust(self, generator, low_trust_report):
        policy = generator.generate(low_trust_report)
        assert policy["action"] == "deny"

    def test_deny_revoked(self, generator, revoked_report):
        policy = generator.generate(revoked_report)
        assert policy["action"] == "deny"
        assert policy["restrictions"]["all_blocked"] is True

    def test_no_trust_deny(self, generator):
        report = AttestationReport(server_url="https://unknown.com")
        policy = generator.generate(report)
        assert policy["action"] == "deny"

    def test_generate_json(self, full_trust_report):
        output = PolicyGenerator.generate_json(full_trust_report)
        assert isinstance(output, str)
        assert "trusted.com" in output

    def test_policy_contains_server_url(self, generator, full_trust_report):
        policy = generator.generate(full_trust_report)
        assert policy["server"] == "https://trusted.com"

    def test_policy_contains_trust_score(self, generator, full_trust_report):
        policy = generator.generate(full_trust_report)
        assert policy["trust_score"] == 95.0

    def test_restricted_access_blocked_tools(self, generator):
        from mcp_attest.models import (
            PermissionFinding,
            PermissionResult,
            PermissionRisk,
        )

        report = AttestationReport(
            server_url="https://good.com",
            trust=TrustResult(score=75.0, level=TrustLevel.HIGH),
            permissions=PermissionResult(
                compliant=False,
                findings=[
                    PermissionFinding(
                        tool_name="dangerous",
                        declared_permission="process:execute",
                        actual_permission="process:execute",
                        risk=PermissionRisk.CRITICAL,
                        recommendation="Remove",
                    )
                ],
            ),
        )
        policy = generator.generate(report)
        assert "dangerous" in policy["restrictions"]["blocked_tools"]

    def test_limited_access_timeout(self, generator, medium_trust_report):
        policy = generator.generate(medium_trust_report)
        assert policy["restrictions"]["session_timeout"] == 300

    def test_deny_all_structure(self, generator):
        policy = generator._deny_all("https://test.com")
        assert policy["server"] == "https://test.com"
        assert policy["action"] == "deny"
        assert policy["trust_score"] == 0.0
