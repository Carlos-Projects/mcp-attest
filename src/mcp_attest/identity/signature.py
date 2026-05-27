"""Cryptographic signature-based identity verification.

Supports RSA-PKCS1v15 and RSA-PSS signature schemes with SHA-256.
"""

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

    Supports RSA keys with PKCS1v15 (default) or PSS signature schemes
    using SHA-256. Non-RSA keys are rejected with a clear error message.
    """

    def __init__(self, pss_mode: bool = False) -> None:
        self.pss_mode = pss_mode
        self._padding = (
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            )
            if pss_mode
            else padding.PKCS1v15()
        )

    @property
    def algorithm(self) -> str:
        return "RSA-PSS-SHA256" if self.pss_mode else "RSA-SHA256"

    async def verify(
        self, server_url: str, identity_data: dict[str, Any]
    ) -> IdentityResult:
        public_key_pem = identity_data.get("public_key")
        signature_b64 = identity_data.get("signature")
        message = identity_data.get("message", server_url)
        pss_mode = identity_data.get("pss_mode", self.pss_mode)

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

            sig_padding = (
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                )
                if pss_mode
                else padding.PKCS1v15()
            )
            alg = "RSA-PSS-SHA256" if pss_mode else "RSA-SHA256"

            signature = base64.b64decode(signature_b64)
            message_bytes = message.encode() if isinstance(message, str) else message
            digest = hashlib.sha256(message_bytes).digest()

            public_key.verify(
                signature,
                digest,
                sig_padding,
                utils.Prehashed(hashes.SHA256()),
            )

            return IdentityResult(
                verified=True,
                method=IdentityMethod.CRYPTO_SIGNATURE,
                subject=server_url,
                issuer=identity_data.get("issuer", "self-signed"),
                details={
                    "algorithm": alg,
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
    def sign_message(private_key_pem: str, message: str, pss_mode: bool = False) -> str:
        """Sign a message with an RSA private key.

        Args:
            private_key_pem: PEM-encoded RSA private key.
            message: Message to sign.
            pss_mode: Use RSA-PSS instead of PKCS1v15.

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

        sig_padding = (
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            )
            if pss_mode
            else padding.PKCS1v15()
        )

        message_bytes = message.encode()
        digest = hashlib.sha256(message_bytes).digest()
        signature = private_key.sign(
            digest,
            sig_padding,
            utils.Prehashed(hashes.SHA256()),
        )
        return base64.b64encode(signature).decode()
