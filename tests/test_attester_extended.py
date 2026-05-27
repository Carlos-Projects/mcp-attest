from datetime import UTC, datetime

import pytest

from mcp_attest.attester import Attester
from mcp_attest.models import (
    IdentityMethod,
    IdentityResult,
    IntegrityResult,
    IntegrityStatus,
    PermissionResult,
    ServerManifest,
    ToolDeclaration,
    TrustLevel,
)


class TestAttesterFullAttestation:
    @pytest.mark.asyncio
    async def test_full_attestation_unreachable(self):
        attester = Attester()
        report = await attester.full_attestation(
            server_url="https://localhost:1",
            method=IdentityMethod.TLS_CERT,
            identity_data={},
        )
        assert report.server_url == "https://localhost:1"
        assert report.identity is not None
        assert report.integrity is not None
        assert report.permissions is not None
        assert report.trust is not None

    @pytest.mark.asyncio
    async def test_full_attestation_with_expected_manifest(self):
        attester = Attester()
        expected = ServerManifest(
            server_url="https://localhost:1",
            server_name="test",
            version="1.0.0",
            tools=[],
            identity_method=IdentityMethod.TLS_CERT,
        )
        report = await attester.full_attestation(
            server_url="https://localhost:1",
            method=IdentityMethod.TLS_CERT,
            identity_data={},
            expected_manifest=expected,
        )
        assert report.integrity is not None
        assert report.trust is not None

    @pytest.mark.asyncio
    async def test_full_attestation_with_revocation(self):
        attester = Attester(revocation_list=["https://revoked.test"])
        report = await attester.full_attestation(
            server_url="https://revoked.test",
            method=IdentityMethod.TLS_CERT,
            identity_data={},
        )
        assert report.trust is not None
        assert report.trust.revoked is True
        assert report.trust.score == 0.0


class TestAttesterVerifyIdentity:
    @pytest.mark.asyncio
    async def test_verify_identity_signature(self):
        attester = Attester()
        result = await attester.verify_identity(
            "https://test.com",
            IdentityMethod.CRYPTO_SIGNATURE,
            {"public_key": "bad"},
        )
        assert result.method == IdentityMethod.CRYPTO_SIGNATURE
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_identity_did(self):
        attester = Attester()
        result = await attester.verify_identity(
            "https://test.com",
            IdentityMethod.DID,
            {"did": "not-valid"},
        )
        assert result.method == IdentityMethod.DID
        assert result.verified is False


class TestAttesterVerifyIntegrity:
    @pytest.mark.asyncio
    async def test_verify_integrity_no_expected(self):
        attester = Attester()
        result = await attester.verify_integrity("https://localhost:1")
        assert result.status == IntegrityStatus.VERIFIED
        assert len(result.manifest_hash) == 64
        assert len(result.fingerprint) == 64

    @pytest.mark.asyncio
    async def test_verify_integrity_with_expected(self):
        attester = Attester()
        expected = ServerManifest(
            server_url="https://localhost:1",
            server_name="test",
            version="1.0.0",
            tools=[ToolDeclaration(name="tool1", description="d", input_schema={})],
            identity_method=IdentityMethod.TLS_CERT,
        )
        result = await attester.verify_integrity(
            "https://localhost:1", expected_manifest=expected
        )
        assert result.expected_hash != ""
        assert result.expected_fingerprint != ""


class TestAttesterAuditPermissions:
    @pytest.mark.asyncio
    async def test_audit_permissions_live(self):
        attester = Attester()
        result = await attester.audit_permissions("https://localhost:1")
        assert result.compliant is True
        assert result.least_privilege_score == 100.0

    @pytest.mark.asyncio
    async def test_audit_permissions_with_manifest(self):
        attester = Attester()
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="exec",
                    description="Exec",
                    input_schema={},
                    permissions=["process:execute"],
                )
            ],
            identity_method=IdentityMethod.TLS_CERT,
        )
        result = await attester.audit_permissions(
            "https://test.com", declared_manifest=manifest
        )
        assert result.compliant is False


class TestAttesterTrustCalculation:
    def test_calculate_trust_with_reputation(self):
        attester = Attester()
        identity = IdentityResult(
            verified=True,
            method=IdentityMethod.TLS_CERT,
            subject="CN=test",
            issuer="CN=CA",
            details={"chain_verified": True},
        )
        integrity = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="h",
            fingerprint="f",
        )
        permissions = PermissionResult(compliant=True, least_privilege_score=100.0)
        trust = attester.calculate_trust(
            identity, integrity, permissions, "https://test.com"
        )
        assert trust.score >= 80.0
        assert trust.level in (TrustLevel.HIGH, TrustLevel.FULL)

    def test_calculate_trust_partial_identity(self):
        attester = Attester()
        identity = IdentityResult(
            verified=True,
            method=IdentityMethod.TLS_CERT,
            subject="CN=test",
        )
        integrity = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="h",
            fingerprint="f",
        )
        permissions = PermissionResult(compliant=True, least_privilege_score=100.0)
        trust = attester.calculate_trust(
            identity, integrity, permissions, "https://test.com"
        )
        assert trust.identity_score >= 50.0
        assert trust.identity_score < 85.0

    def test_score_identity_with_validity_dates(self):
        attester = Attester()
        now = datetime.now(UTC)
        identity = IdentityResult(
            verified=True,
            method=IdentityMethod.TLS_CERT,
            subject="CN=test",
            issuer="CN=CA",
            valid_from=now,
            valid_to=now,
        )
        score = attester._score_identity(identity)
        assert score >= 85.0

    def test_score_integrity_unknown(self):
        attester = Attester()
        integrity = IntegrityResult(
            status=IntegrityStatus.UNKNOWN,
            manifest_hash="h",
            fingerprint="f",
        )
        score = attester._score_integrity(integrity)
        assert score == 50.0
