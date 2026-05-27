"""Cryptographic signature-based identity verification."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from mcp_attest.models import IdentityMethod, IdentityResult


class SignatureVerifier:
    """Verifies MCP server identity via cryptographic signatures.

    Supports RSA keys with PKCS1v15 signature scheme using SHA-256.
    Non-RSA keys are rejected with a clear error message.
    """

    async def verify(
        self, server_url: str, identity_data: dict[str, Any]
    ) -> IdentityResult:
        public_key_pem = identity_data.get("public_key")
        signature_b64 = identity_data.get("signature")
        message = identity_data.get("message", server_url)

        if not public_key_pem or not signature_b64:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.CRYPTO_SIGNATURE,
                subject=server_url,
                details={"error": "Missing public_key or signature"},
            )

        try:
            key_bytes = (
                public_key_pem.encode()
                if isinstance(public_key_pem, str)
                else public_key_pem
            )
            public_key = serialization.load_pem_public_key(key_bytes)

            # Validate key type — only RSA supported
            if not isinstance(public_key, rsa.RSAPublicKey):
                return IdentityResult(
                    verified=False,
                    method=IdentityMethod.CRYPTO_SIGNATURE,
                    subject=server_url,
                    details={
                        "error": (
                            f"Unsupported key type: {type(public_key).__name__}. "
                            "Only RSA keys are supported."
                        )
                    },
                )

            signature = base64.b64decode(signature_b64)
            message_bytes = message.encode() if isinstance(message, str) else message
            digest = hashlib.sha256(message_bytes).digest()

            public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )

            return IdentityResult(
                verified=True,
                method=IdentityMethod.CRYPTO_SIGNATURE,
                subject=server_url,
                issuer=identity_data.get("issuer", "self-signed"),
                details={
                    "algorithm": "RSA-SHA256",
                    "key_size": public_key.key_size,
                },
            )
        except InvalidSignature:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.CRYPTO_SIGNATURE,
                subject=server_url,
                details={"error": "Signature verification failed"},
            )
        except Exception as exc:
            return IdentityResult(
                verified=False,
                method=IdentityMethod.CRYPTO_SIGNATURE,
                subject=server_url,
                details={"error": f"Invalid key or signature format: {exc}"},
            )

    @staticmethod
    def sign_message(private_key_pem: str, message: str) -> str:
        """Sign a message with an RSA private key.

        Note: This method is intended for testing and key generation,
        not for production key management.
        """
        key_bytes = (
            private_key_pem.encode()
            if isinstance(private_key_pem, str)
            else private_key_pem
        )
        private_key = serialization.load_pem_private_key(key_bytes, password=None)

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError(
                f"Unsupported key type: {type(private_key).__name__}. "
                "Only RSA private keys are supported."
            )

        message_bytes = message.encode()
        digest = hashlib.sha256(message_bytes).digest()
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
        return base64.b64encode(signature).decode()
