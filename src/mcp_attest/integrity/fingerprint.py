"""Capability fingerprinting for MCP servers."""

from __future__ import annotations

import hashlib
import json

from mcp_attest.models import ServerManifest, ToolDeclaration


class CapabilityFingerprinter:
    """Creates unique fingerprints from server capability manifests."""

    def compute(self, manifest: ServerManifest) -> str:
        tool_signatures = []
        for tool in sorted(manifest.tools, key=lambda t: t.name):
            signature = self._tool_signature(tool)
            tool_signatures.append(signature)

        combined = json.dumps(tool_signatures, sort_keys=True)
        return hashlib.sha256(combined.encode()).hexdigest()

    @staticmethod
    def _tool_signature(tool: ToolDeclaration) -> dict[str, str]:
        schema_hash = hashlib.sha256(
            json.dumps(tool.input_schema, sort_keys=True).encode()
        ).hexdigest()[:16]
        return {
            "name": tool.name,
            "schema_hash": schema_hash,
            "perm_count": str(len(tool.permissions)),
        }

    @staticmethod
    def compare(fp1: str, fp2: str) -> bool:
        return fp1 == fp2
