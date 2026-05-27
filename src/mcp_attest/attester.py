"""Core attestation engine for MCP servers."""

from __future__ import annotations

from typing import Any

from mcp_attest.identity.did import DIDVerifier
from mcp_attest.identity.signature import SignatureVerifier
from mcp_attest.identity.tls import TLSVerifier
from mcp_attest.integrity.diff import ManifestDiffer
from mcp_attest.integrity.fingerprint import CapabilityFingerprinter
from mcp_attest.integrity.manifest import ManifestGenerator
from mcp_attest.models import (
    AttestationReport,
    IdentityMethod,
    IdentityResult,
    IntegrityResult,
    IntegrityStatus,
    PermissionResult,
    ServerManifest,
    TrustResult,
)
from mcp_attest.permissions.auditor import PermissionAuditor
from mcp_attest.trust.revocation import RevocationChecker
from mcp_attest.trust.scorer import TrustScorer

# Default trust score weights
DEFAULT_WEIGHTS: dict[str, float] = {
    "identity": 0.30,
    "integrity": 0.35,
    "permission": 0.20,
    "reputation": 0.15,
}


class Attester:
    """Core engine that orchestrates identity, integrity, and trust attestation.

    Args:
        revocation_list: List of revoked server URLs or fingerprints.
        trust_threshold: Minimum trust score (0-100) to allow access.
        allow_private_ips: Allow connections to private/ RFC 1918 IPs.
        weights: Custom trust score weights (must sum to 1.0).
        dangerous_permissions: Custom mapping of permission strings to PermissionRisk.
    """

    def __init__(
        self,
        revocation_list: list[str] | None = None,
        trust_threshold: float = 50.0,
        allow_private_ips: bool = False,
        weights: dict[str, float] | None = None,
        dangerous_permissions: dict[str, Any] | None = None,
    ) -> None:
        self.tls_verifier = TLSVerifier()
        self.signature_verifier = SignatureVerifier()
        self.did_verifier = DIDVerifier()
        self.manifest_generator = ManifestGenerator(allow_private=allow_private_ips)
        self.fingerprinter = CapabilityFingerprinter()
        self.differ = ManifestDiffer()
        self.permission_auditor = PermissionAuditor(
            custom_permissions=dangerous_permissions
        )
        self.trust_scorer = TrustScorer(weights=weights or DEFAULT_WEIGHTS)
        self.revocation_checker = RevocationChecker(revocation_list or [])
        self.trust_threshold = trust_threshold

    async def verify_identity(
        self, server_url: str, method: IdentityMethod, identity_data: dict[str, Any]
    ) -> IdentityResult:
        if method == IdentityMethod.TLS_CERT:
            return await self.tls_verifier.verify(server_url, identity_data)
        if method == IdentityMethod.CRYPTO_SIGNATURE:
            return await self.signature_verifier.verify(server_url, identity_data)
        if method == IdentityMethod.DID:
            return await self.did_verifier.verify(server_url, identity_data)
        raise ValueError(f"Unknown identity method: {method}")

    async def verify_integrity(
        self,
        server_url: str,
        expected_manifest: ServerManifest | None = None,
    ) -> IntegrityResult:
        live_manifest = await self.manifest_generator.generate(server_url)
        fingerprint = self.fingerprinter.compute(live_manifest)
        live_manifest.compute_hash()

        result = IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash=live_manifest.manifest_hash,
            fingerprint=fingerprint,
        )

        if expected_manifest:
            expected_manifest.compute_hash()
            result.expected_hash = expected_manifest.manifest_hash
            result.expected_fingerprint = self.fingerprinter.compute(expected_manifest)

            diff = self.differ.compare(expected_manifest, live_manifest)
            result.added_tools = diff.added
            result.removed_tools = diff.removed
            result.changed_tools = diff.modified

            if diff.has_changes():
                result.status = IntegrityStatus.MODIFIED

        return result

    async def audit_permissions(
        self,
        server_url: str,
        declared_manifest: ServerManifest | None = None,
    ) -> PermissionResult:
        if declared_manifest:
            return await self.permission_auditor.audit(declared_manifest)

        live_manifest = await self.manifest_generator.generate(server_url)
        return await self.permission_auditor.audit(live_manifest)

    def calculate_trust(
        self,
        identity: IdentityResult,
        integrity: IntegrityResult,
        permissions: PermissionResult,
        server_url: str,
    ) -> TrustResult:
        revoked = self.revocation_checker.is_revoked(server_url)

        identity_score = self._score_identity(identity)
        integrity_score = self._score_integrity(integrity)
        permission_score = permissions.least_privilege_score

        trust = self.trust_scorer.calculate(
            identity_score=identity_score,
            integrity_score=integrity_score,
            permission_score=permission_score,
            reputation_score=0.0,
            revoked=revoked,
        )

        return TrustResult(
            score=trust.score,
            level=trust.level,
            identity_score=identity_score,
            integrity_score=integrity_score,
            permission_score=permission_score,
            reputation_score=0.0,
            revoked=revoked,
            details=trust.details,
        )

    async def full_attestation(
        self,
        server_url: str,
        method: IdentityMethod,
        identity_data: dict[str, Any],
        expected_manifest: ServerManifest | None = None,
    ) -> AttestationReport:
        identity = await self.verify_identity(server_url, method, identity_data)
        integrity = await self.verify_integrity(server_url, expected_manifest)
        permissions = await self.permission_auditor.audit(
            expected_manifest or await self.manifest_generator.generate(server_url)
        )
        trust = self.calculate_trust(identity, integrity, permissions, server_url)

        policy = "allow" if trust.score >= self.trust_threshold else "deny"

        return AttestationReport(
            server_url=server_url,
            identity=identity,
            integrity=integrity,
            permissions=permissions,
            trust=trust,
            policy_recommended=policy,
        )

    @staticmethod
    def _score_identity(result: IdentityResult) -> float:
        if not result.verified:
            return 0.0
        score = 50.0
        if result.issuer:
            score += 20.0
        if result.valid_from and result.valid_to:
            score += 15.0
        if result.details.get("chain_verified"):
            score += 15.0
        return min(score, 100.0)

    @staticmethod
    def _score_integrity(result: IntegrityResult) -> float:
        if result.status == IntegrityStatus.VERIFIED:
            return 100.0
        if result.status == IntegrityStatus.MODIFIED:
            penalty = (
                len(result.added_tools) * 10
                + len(result.removed_tools) * 15
                + len(result.changed_tools) * 20
            )
            return max(0.0, 100.0 - penalty)
        return 50.0
