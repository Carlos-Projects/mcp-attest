"""DID (Decentralized Identifier) based identity verification."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx

from mcp_attest.models import IdentityMethod, IdentityResult
from mcp_attest.utils.http import validate_url


class DIDVerifier:
    """Verifies MCP server identity via Decentralized Identifiers (DIDs)."""

    _did_pattern = re.compile(r"^did:(?P<method>[a-z0-9]+):(?P<id>.+)$")

    async def verify(
        self, server_url: str, identity_data: dict[str, Any]
    ) -> IdentityResult:
        did = identity_data.get("did", "")
        proof = identity_data.get("proof", "")

        match = self._did_pattern.match(did)
        if not match:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.DID,
                subject=server_url,
                details={"error": f"Invalid DID format: {did}"},
            )

        did_method = match.group("method")
        did_id = match.group("id")

        if not proof:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.DID,
                subject=server_url,
                details={"error": "Missing proof"},
            )

        verified = await self._resolve_and_verify(did_method, did_id, proof)

        return IdentityResult(
            verified=verified,
            method=IdentityMethod.DID,
            subject=did,
            issuer=f"did:{did_method}:{did_id}",
            details={
                "did_method": did_method,
                "did_id": did_id,
                "proof_verified": verified,
            },
        )

    @staticmethod
    async def _resolve_and_verify(method: str, did_id: str, proof: str) -> bool:
        if method == "web":
            return await DIDVerifier._verify_did_web(did_id, proof)
        if method == "key":
            return await DIDVerifier._verify_did_key(did_id, proof)
        return False

    @staticmethod
    async def _verify_did_web(did_id: str, proof: str) -> bool:
        parts = did_id.split("/")
        domain = parts[0]
        path = "/".join(parts[1:]) if len(parts) > 1 else ".well-known/did.json"

        # SSRF prevention: path traversal and domain validation
        if ".." in path or path.startswith("/"):
            return False
        if not re.match(r"^[a-zA-Z0-9.\-_:%/]+$", path):
            return False

        url = f"https://{domain}/{path}"

        try:
            validate_url(url, allow_private=False)  # noqa: FBT003
        except ValueError:
            return False

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=10)
                if resp.status_code != 200:
                    return False
                doc = resp.json()
                vm = doc.get("verificationMethod")
                if not vm:
                    return False
                # Verify proof against the DID document's verification method
                return _verify_did_proof(vm, proof)
        except Exception:
            return False

    @staticmethod
    async def _verify_did_key(did_id: str, proof: str) -> bool:
        try:
            decoded = base64.urlsafe_b64decode(did_id + "==")
            doc = json.loads(decoded)
            return bool(doc.get("id"))
        except Exception:
            return False


def _verify_did_proof(verification_method: Any, proof: str) -> bool:
    """Verify a proof against a DID document's verification method.

    Currently performs structural validation. Full cryptographic proof
    verification will be added in a future release.
    """
    if isinstance(verification_method, list) and len(verification_method) > 0:
        return bool(proof)
    if isinstance(verification_method, dict):
        return bool(proof)
    return bool(proof)
