import pytest

from mcp_attest.identity.signature import SignatureVerifier
from mcp_attest.utils.crypto import generate_key_pair


class TestSignatureVerifierExtended:
    @pytest.fixture
    def verifier(self):
        return SignatureVerifier()

    @pytest.mark.asyncio
    async def test_verify_invalid_signature(self, verifier):
        _, public_pem = generate_key_pair()
        import base64

        wrong_sig = base64.b64encode(b"\x00" * 256).decode()
        result = await verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": wrong_sig,
                "message": "test",
            },
        )
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_valid_signature(self, verifier):
        private_pem, public_pem = generate_key_pair()
        message = "test message"
        signature = SignatureVerifier.sign_message(private_pem, message)
        result = await verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": signature,
                "message": message,
            },
        )
        assert result.verified is True
        assert result.details.get("algorithm") == "RSA-SHA256"

    @pytest.mark.asyncio
    async def test_verify_with_bytes_key(self, verifier):
        private_pem, public_pem = generate_key_pair()
        message = "test"
        signature = SignatureVerifier.sign_message(private_pem, message)
        result = await verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem.encode(),
                "signature": signature,
                "message": message,
            },
        )
        assert result.verified is True

    @pytest.mark.asyncio
    async def test_verify_with_bytes_message(self, verifier):
        private_pem, public_pem = generate_key_pair()
        message = "test"
        signature = SignatureVerifier.sign_message(private_pem, message)
        result = await verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": signature,
                "message": message.encode(),
            },
        )
        assert result.verified is True

    @pytest.mark.asyncio
    async def test_verify_with_bytes_private_key(self, verifier):
        private_pem, public_pem = generate_key_pair()
        message = "test"
        signature = SignatureVerifier.sign_message(private_pem.encode(), message)
        assert isinstance(signature, str)

    @pytest.mark.asyncio
    async def test_verify_malformed_public_key(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {
                "public_key": "not-a-valid-pem-key",
                "signature": "dGVzdA==",
                "message": "test",
            },
        )
        assert result.verified is False
        assert "error" in result.details

    @pytest.mark.asyncio
    async def test_rejects_non_rsa_key(self, verifier):
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP256R1())
        from cryptography.hazmat.primitives import serialization

        public_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        result = await verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": "dGVzdA==",
                "message": "test",
            },
        )
        assert result.verified is False
        assert "Unsupported key type" in result.details.get("error", "")

    def test_sign_message_rejects_non_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        private_key = ec.generate_private_key(ec.SECP256R1())
        from cryptography.hazmat.primitives import serialization

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        with pytest.raises(TypeError, match="Unsupported key type"):
            SignatureVerifier.sign_message(pem, "test")
