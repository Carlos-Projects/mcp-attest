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


@pytest.fixture
def attester():
    return Attester(revocation_list=["https://revoked.example.com"])


@pytest.fixture
def sample_manifest():
    return ServerManifest(
        server_url="https://mcp.example.com",
        server_name="test-server",
        version="1.0.0",
        tools=[
            ToolDeclaration(
                name="read_file",
                description="Read a file",
                input_schema={"type": "object"},
                permissions=["filesystem:read"],
            ),
            ToolDeclaration(
                name="write_file",
                description="Write a file",
                input_schema={"type": "object"},
                permissions=["filesystem:write"],
            ),
        ],
        identity_method=IdentityMethod.TLS_CERT,
    )


class TestAttesterIdentity:
    @pytest.mark.asyncio
    async def test_verify_identity_tls(self, attester):
        result = await attester.verify_identity(
            "https://example.com", IdentityMethod.TLS_CERT, {}
        )
        assert isinstance(result, IdentityResult)
        assert result.method == IdentityMethod.TLS_CERT

    @pytest.mark.asyncio
    async def test_verify_identity_unknown_method(self, attester):
        with pytest.raises(ValueError):
            await attester.verify_identity(
                "https://example.com", "unknown", {}
            )

    def test_score_identity_verified(self, attester):
        identity = IdentityResult(
            verified=True,
            method=IdentityMethod.TLS_CERT,
            subject="CN=example.com",
            issuer="CN=Let's Encrypt",
        )
        score = attester._score_identity(identity)
        assert score >= 50.0

    def test_score_identity_not_verified(self, attester):
        identity = IdentityResult(
            verified=False,
            method=IdentityMethod.TLS_CERT,
            subject="https://example.com",
        )
        score = attester._score_identity(identity)
        assert score == 0.0

    def test_score_identity_with_chain(self, attester):
        identity = IdentityResult(
            verified=True,
            method=IdentityMethod.TLS_CERT,
            subject="CN=example.com",
            issuer="CN=CA",
            details={"chain_verified": True},
        )
        score = attester._score_identity(identity)
        assert score >= 85.0


class TestAttesterIntegrity:
    def test_score_integrity_verified(self, attester):
        integrity = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
        )
        score = attester._score_integrity(integrity)
        assert score == 100.0

    def test_score_integrity_modified_no_changes(self, attester):
        integrity = IntegrityResult(
            status=IntegrityStatus.MODIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
        )
        score = attester._score_integrity(integrity)
        assert score == 100.0

    def test_score_integrity_with_added_tools(self, attester):
        integrity = IntegrityResult(
            status=IntegrityStatus.MODIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
            added_tools=["new_tool"],
        )
        score = attester._score_integrity(integrity)
        assert score == 90.0

    def test_score_integrity_with_removed_tools(self, attester):
        integrity = IntegrityResult(
            status=IntegrityStatus.MODIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
            removed_tools=["old_tool"],
        )
        score = attester._score_integrity(integrity)
        assert score == 85.0

    def test_score_integrity_with_changed_tools(self, attester):
        integrity = IntegrityResult(
            status=IntegrityStatus.MODIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
            changed_tools=["modified_tool"],
        )
        score = attester._score_integrity(integrity)
        assert score == 80.0

    def test_score_integrity_multiple_changes(self, attester):
        integrity = IntegrityResult(
            status=IntegrityStatus.MODIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
            added_tools=["t1", "t2"],
            removed_tools=["t3"],
            changed_tools=["t4"],
        )
        score = attester._score_integrity(integrity)
        assert score == 45.0


class TestAttesterTrust:
    def test_calculate_trust_full(self, attester):
        identity = IdentityResult(
            verified=True, method=IdentityMethod.TLS_CERT, subject="test"
        )
        integrity = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="h",
            fingerprint="f",
        )
        permissions = PermissionResult(
            compliant=True, least_privilege_score=100.0
        )

        trust = attester.calculate_trust(identity, integrity, permissions, "https://test.com")
        assert trust.score > 0
        assert not trust.revoked

    def test_calculate_trust_revoked(self, attester):
        identity = IdentityResult(
            verified=True, method=IdentityMethod.TLS_CERT, subject="test"
        )
        integrity = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="h",
            fingerprint="f",
        )
        permissions = PermissionResult(
            compliant=True, least_privilege_score=100.0
        )

        trust = attester.calculate_trust(
            identity, integrity, permissions, "https://revoked.example.com"
        )
        assert trust.score == 0.0
        assert trust.revoked
        assert trust.level == TrustLevel.UNTRUSTED

    def test_calculate_trust_low_identity(self, attester):
        identity = IdentityResult(
            verified=False, method=IdentityMethod.TLS_CERT, subject="test"
        )
        integrity = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="h",
            fingerprint="f",
        )
        permissions = PermissionResult(
            compliant=True, least_privilege_score=100.0
        )

        trust = attester.calculate_trust(identity, integrity, permissions, "https://test.com")
        assert trust.identity_score == 0.0


class TestAttesterManifest:
    def test_manifest_compute_hash(self, sample_manifest):
        h1 = sample_manifest.compute_hash()
        assert len(h1) == 64
        h2 = sample_manifest.compute_hash()
        assert h1 == h2

    def test_manifest_hash_changes_with_tools(self, sample_manifest):
        h1 = sample_manifest.compute_hash()
        sample_manifest.tools.append(
            ToolDeclaration(name="new_tool", description="new")
        )
        h2 = sample_manifest.compute_hash()
        assert h1 != h2

    def test_manifest_hash_changes_with_version(self, sample_manifest):
        h1 = sample_manifest.compute_hash()
        sample_manifest.version = "2.0.0"
        h2 = sample_manifest.compute_hash()
        assert h1 != h2
