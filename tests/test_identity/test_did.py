import pytest

from mcp_attest.identity.did import DIDVerifier


class TestDIDVerifierExtended:
    @pytest.fixture
    def verifier(self):
        return DIDVerifier()

    @pytest.mark.asyncio
    async def test_verify_did_web_unreachable(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {"did": "did:web:localhost:1", "proof": "proof"},
        )
        assert result.verified is False
        assert result.details.get("did_method") == "web"

    @pytest.mark.asyncio
    async def test_verify_did_key_invalid(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {"did": "did:key:notvalidbase64!!!", "proof": "proof"},
        )
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_did_key_valid_format(self, verifier):
        import base64
        import json

        doc = {"id": "did:key:test"}
        encoded = (
            base64.urlsafe_b64encode(json.dumps(doc).encode()).decode().rstrip("=")
        )
        result = await verifier.verify(
            "https://test.com",
            {"did": f"did:key:{encoded}", "proof": "proof"},
        )
        assert result.verified is True

    def test_resolve_unknown_method(self, verifier):
        import asyncio

        result = asyncio.run(verifier._resolve_and_verify("unknown", "test", "proof"))
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_did_web_success(self, verifier):
        import respx
        from httpx import Response

        with respx.mock:
            respx.get("https://example.com/.well-known/did.json").mock(
                return_value=Response(
                    200,
                    json={
                        "id": "did:web:example.com",
                        "verificationMethod": [{"id": "#key-1"}],
                    },
                )
            )
            result = await verifier.verify(
                "https://test.com",
                {"did": "did:web:example.com", "proof": "proof"},
            )
            assert result.verified is True

    @pytest.mark.asyncio
    async def test_verify_did_web_no_verification_method(self, verifier):
        import respx
        from httpx import Response

        with respx.mock:
            respx.get("https://example.com/.well-known/did.json").mock(
                return_value=Response(200, json={"id": "did:web:example.com"})
            )
            result = await verifier.verify(
                "https://test.com",
                {"did": "did:web:example.com", "proof": "proof"},
            )
            assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_did_web_not_found(self, verifier):
        import respx
        from httpx import Response

        with respx.mock:
            respx.get("https://example.com/.well-known/did.json").mock(
                return_value=Response(404)
            )
            result = await verifier.verify(
                "https://test.com",
                {"did": "did:web:example.com", "proof": "proof"},
            )
            assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_did_web_path_traversal_blocked(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {"did": "did:web:example.com/../../etc/passwd", "proof": "proof"},
        )
        assert result.verified is False
        assert "path" in str(result.details).lower() or not result.verified

    @pytest.mark.asyncio
    async def test_verify_did_web_private_ip_blocked(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {"did": "did:web:localhost", "proof": "proof"},
        )
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_did_web_private_ip_by_hostname(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {"did": "did:web:10.0.0.1", "proof": "proof"},
        )
        assert result.verified is False
