"""Core data models for MCP Attest."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IdentityMethod(StrEnum):
    TLS_CERT = "tls_cert"
    CRYPTO_SIGNATURE = "crypto_signature"
    DID = "did"


class IntegrityStatus(StrEnum):
    VERIFIED = "verified"
    MODIFIED = "modified"
    UNKNOWN = "unknown"


class PermissionRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(StrEnum):
    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    FULL = "full"


class ToolDeclaration(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    risk_level: PermissionRisk = PermissionRisk.LOW
    permissions: list[str] = Field(default_factory=list)


class ServerManifest(BaseModel):
    server_url: str
    server_name: str
    version: str
    tools: list[ToolDeclaration] = Field(default_factory=list)
    identity_method: IdentityMethod
    identity_data: dict[str, Any] = Field(default_factory=dict)
    manifest_hash: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    def compute_hash(self) -> str:
        import hashlib
        import json

        payload = json.dumps(
            {
                "server_url": self.server_url,
                "server_name": self.server_name,
                "version": self.version,
                "tools": sorted(
                    [t.model_dump() for t in self.tools], key=lambda x: x["name"]
                ),
            },
            sort_keys=True,
        )
        self.manifest_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self.manifest_hash


class IdentityResult(BaseModel):
    verified: bool
    method: IdentityMethod
    subject: str
    issuer: str = ""
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IntegrityResult(BaseModel):
    status: IntegrityStatus
    manifest_hash: str = ""
    expected_hash: str = ""
    fingerprint: str = ""
    expected_fingerprint: str = ""
    changed_tools: list[str] = Field(default_factory=list)
    added_tools: list[str] = Field(default_factory=list)
    removed_tools: list[str] = Field(default_factory=list)


class PermissionFinding(BaseModel):
    tool_name: str
    declared_permission: str
    actual_permission: str
    risk: PermissionRisk
    recommendation: str


class PermissionResult(BaseModel):
    compliant: bool
    findings: list[PermissionFinding] = Field(default_factory=list)
    least_privilege_score: float = 100.0


class TrustResult(BaseModel):
    score: float = Field(ge=0, le=100)
    level: TrustLevel
    identity_score: float = 0.0
    integrity_score: float = 0.0
    permission_score: float = 0.0
    reputation_score: float = 0.0
    revoked: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class AttestationReport(BaseModel):
    server_url: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    identity: IdentityResult | None = None
    integrity: IntegrityResult | None = None
    permissions: PermissionResult | None = None
    trust: TrustResult | None = None
    policy_recommended: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
