"""Tests for RSA-PSS signature support."""

import pytest

from mcp_attest.identity.signature import SignatureVerifier
from mcp_attest.utils.crypto import generate_key_pair


class TestSignaturePSS:
    @pytest.fixture
    def pss_verifier(self):
        return SignatureVerifier(pss_mode=True)

    @pytest.fixture
    def pkcs1_verifier(self):
        return SignatureVerifier(pss_mode=False)

    def test_algorithm_property_pss(self, pss_verifier):
        assert pss_verifier.algorithm == "RSA-PSS-SHA256"

    def test_algorithm_property_pkcs1(self, pkcs1_verifier):
        assert pkcs1_verifier.algorithm == "RSA-SHA256"

    @pytest.mark.asyncio
    async def test_verify_pss_valid_signature(self, pss_verifier):
        private_pem, public_pem = generate_key_pair()
        message = "test message"
        signature = SignatureVerifier.sign_message(private_pem, message, pss_mode=True)
        result = await pss_verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": signature,
                "message": message,
            },
        )
        assert result.verified is True
        assert result.details.get("algorithm") == "RSA-PSS-SHA256"

    @pytest.mark.asyncio
    async def test_verify_pss_invalid_signature(self, pss_verifier):
        private_pem, public_pem = generate_key_pair()
        import base64

        wrong_sig = base64.b64encode(b"\x00" * 256).decode()
        result = await pss_verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": wrong_sig,
                "message": "test",
            },
        )
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_pss_via_identity_data(self, pkcs1_verifier):
        """Verify pss_mode can be set per-call via identity_data."""
        private_pem, public_pem = generate_key_pair()
        message = "test"
        signature = SignatureVerifier.sign_message(private_pem, message, pss_mode=True)
        result = await pkcs1_verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": signature,
                "message": message,
                "pss_mode": True,
            },
        )
        assert result.verified is True
        assert result.details.get("algorithm") == "RSA-PSS-SHA256"

    @pytest.mark.asyncio
    async def test_pkcs1_fails_pss_signature(self, pkcs1_verifier):
        """PKCS1v15 verifier should fail on a PSS signature."""
        private_pem, public_pem = generate_key_pair()
        message = "test"
        signature = SignatureVerifier.sign_message(private_pem, message, pss_mode=True)
        result = await pkcs1_verifier.verify(
            "https://test.com",
            {
                "public_key": public_pem,
                "signature": signature,
                "message": message,
            },
        )
        assert result.verified is False

    def test_sign_message_pss(self):
        private_pem, _ = generate_key_pair()
        signature = SignatureVerifier.sign_message(private_pem, "test", pss_mode=True)
        assert isinstance(signature, str)
        assert len(signature) > 0
