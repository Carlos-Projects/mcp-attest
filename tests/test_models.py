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
    ServerManifest,
    ToolDeclaration,
    TrustLevel,
    TrustResult,
)


class TestToolDeclaration:
    def test_create_minimal(self):
        tool = ToolDeclaration(name="test", description="desc")
        assert tool.name == "test"
        assert tool.input_schema == {}
        assert tool.permissions == []
        assert tool.risk_level == PermissionRisk.LOW


class TestServerManifest:
    def test_create_minimal(self):
        m = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            identity_method=IdentityMethod.TLS_CERT,
        )
        assert m.tools == []
        assert m.manifest_hash == ""

    def test_compute_hash(self):
        m = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            identity_method=IdentityMethod.TLS_CERT,
        )
        h = m.compute_hash()
        assert len(h) == 64

    def test_hash_deterministic(self):
        m = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            identity_method=IdentityMethod.TLS_CERT,
        )
        h1 = m.compute_hash()
        h2 = m.compute_hash()
        assert h1 == h2


class TestIdentityResult:
    def test_create_verified(self):
        r = IdentityResult(
            verified=True, method=IdentityMethod.TLS_CERT, subject="test"
        )
        assert r.verified is True
        assert r.details == {}


class TestIntegrityResult:
    def test_create_verified(self):
        r = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="abc",
            fingerprint="fp",
        )
        assert r.status == IntegrityStatus.VERIFIED
        assert r.added_tools == []


class TestPermissionResult:
    def test_create_compliant(self):
        r = PermissionResult(compliant=True)
        assert r.compliant is True
        assert r.findings == []
        assert r.least_privilege_score == 100.0


class TestPermissionFinding:
    def test_create(self):
        f = PermissionFinding(
            tool_name="test",
            declared_permission="perm",
            actual_permission="perm",
            risk=PermissionRisk.HIGH,
            recommendation="fix",
        )
        assert f.tool_name == "test"
        assert f.risk == PermissionRisk.HIGH


class TestTrustResult:
    def test_create(self):
        r = TrustResult(score=75.0, level=TrustLevel.HIGH)
        assert r.score == 75.0
        assert r.level == TrustLevel.HIGH
        assert r.revoked is False

    def test_score_bounds(self):
        with pytest.raises(ValueError):
            TrustResult(score=101.0, level=TrustLevel.FULL)


class TestAttestationReport:
    def test_create_minimal(self):
        r = AttestationReport(server_url="https://test.com")
        assert r.server_url == "https://test.com"
        assert r.identity is None
        assert r.trust is None

    def test_to_dict(self):
        r = AttestationReport(server_url="https://test.com")
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["server_url"] == "https://test.com"

    def test_to_dict_with_trust(self):
        r = AttestationReport(
            server_url="https://test.com",
            trust=TrustResult(score=80.0, level=TrustLevel.HIGH),
        )
        d = r.to_dict()
        assert d["trust"]["score"] == 80.0


class TestEnums:
    def test_identity_method_values(self):
        assert IdentityMethod.TLS_CERT.value == "tls_cert"
        assert IdentityMethod.CRYPTO_SIGNATURE.value == "crypto_signature"
        assert IdentityMethod.DID.value == "did"

    def test_integrity_status_values(self):
        assert IntegrityStatus.VERIFIED.value == "verified"
        assert IntegrityStatus.MODIFIED.value == "modified"
        assert IntegrityStatus.UNKNOWN.value == "unknown"

    def test_permission_risk_values(self):
        assert PermissionRisk.LOW.value == "low"
        assert PermissionRisk.MEDIUM.value == "medium"
        assert PermissionRisk.HIGH.value == "high"
        assert PermissionRisk.CRITICAL.value == "critical"

    def test_trust_level_values(self):
        assert TrustLevel.UNTRUSTED.value == "untrusted"
        assert TrustLevel.LOW.value == "low"
        assert TrustLevel.MEDIUM.value == "medium"
        assert TrustLevel.HIGH.value == "high"
        assert TrustLevel.FULL.value == "full"
