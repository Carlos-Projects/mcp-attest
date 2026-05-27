"""MCP Attest — Attested Tool-Server Admission for the Model Context Protocol."""

__version__ = "0.1.0"

from mcp_attest.attester import Attester
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
from mcp_attest.taxonomy import attestation_to_taxonomy_events
from mcp_attest.utils.audit import AuditLogger

__all__ = [
    "Attester",
    "AttestationReport",
    "IdentityMethod",
    "IdentityResult",
    "IntegrityResult",
    "IntegrityStatus",
    "PermissionFinding",
    "PermissionResult",
    "PermissionRisk",
    "ServerManifest",
    "ToolDeclaration",
    "TrustLevel",
    "TrustResult",
    "AuditLogger",
    "attestation_to_taxonomy_events",
]
