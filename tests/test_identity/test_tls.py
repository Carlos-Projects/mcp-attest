import pytest

from mcp_attest.identity.did import DIDVerifier
from mcp_attest.identity.signature import SignatureVerifier
from mcp_attest.identity.tls import TLSVerifier
from mcp_attest.models import IdentityMethod


class TestTLSVerifier:
    @pytest.fixture
    def verifier(self):
        return TLSVerifier()

    @pytest.mark.asyncio
    async def test_verify_invalid_url(self, verifier):
        result = await verifier.verify("not-a-url", {})
        assert not result.verified
        assert result.method == IdentityMethod.TLS_CERT

    @pytest.mark.asyncio
    async def test_verify_unreachable_server(self, verifier):
        result = await verifier.verify("https://localhost:1", {})
        assert not result.verified

    def test_extract_subject_empty(self, verifier):
        subject = verifier._extract_subject({})
        assert subject == "unknown"

    def test_extract_subject_with_data(self, verifier):
        cert = {"subject": ((("CN", "example.com"),),)}
        subject = verifier._extract_subject(cert)
        assert "CN=example.com" in subject

    def test_extract_issuer_empty(self, verifier):
        issuer = verifier._extract_issuer({})
        assert issuer == "unknown"

    def test_extract_issuer_with_data(self, verifier):
        cert = {"issuer": ((("O", "Let's Encrypt"),),)}
        issuer = verifier._extract_issuer(cert)
        assert "O=Let's Encrypt" in issuer


class TestSignatureVerifier:
    @pytest.fixture
    def verifier(self):
        return SignatureVerifier()

    @pytest.mark.asyncio
    async def test_verify_missing_key(self, verifier):
        result = await verifier.verify("https://test.com", {"signature": "abc"})
        assert not result.verified
        assert "Missing" in result.details.get("error", "")

    @pytest.mark.asyncio
    async def test_verify_missing_signature(self, verifier):
        result = await verifier.verify("https://test.com", {"public_key": "pem"})
        assert not result.verified

    def test_sign_and_verify_roundtrip(self, verifier):
        from mcp_attest.utils.crypto import generate_key_pair

        private_pem, public_pem = generate_key_pair()
        message = "test message"
        signature = SignatureVerifier.sign_message(private_pem, message)

        assert isinstance(signature, str)
        assert len(signature) > 0

    def test_sign_message_produces_valid_signature(self, verifier):
        from mcp_attest.utils.crypto import generate_key_pair

        private_pem, public_pem = generate_key_pair()
        sig = SignatureVerifier.sign_message(private_pem, "hello")
        assert sig is not None


class TestDIDVerifier:
    @pytest.fixture
    def verifier(self):
        return DIDVerifier()

    @pytest.mark.asyncio
    async def test_verify_invalid_did_format(self, verifier):
        result = await verifier.verify("https://test.com", {"did": "not-a-did"})
        assert not result.verified
        assert "Invalid DID" in result.details.get("error", "")

    @pytest.mark.asyncio
    async def test_verify_missing_proof(self, verifier):
        result = await verifier.verify(
            "https://test.com", {"did": "did:web:example.com"}
        )
        assert not result.verified
        assert "Missing proof" in result.details.get("error", "")

    @pytest.mark.asyncio
    async def test_verify_unknown_method(self, verifier):
        result = await verifier.verify(
            "https://test.com",
            {"did": "did:unknown:test", "proof": "proof"},
        )
        assert not result.verified

    def test_did_pattern_matches_web(self, verifier):
        match = verifier._did_pattern.match("did:web:example.com%2Fuser")
        assert match is not None
        assert match.group("method") == "web"

    def test_did_pattern_matches_key(self, verifier):
        match = verifier._did_pattern.match("did:key:z6Mktest")
        assert match is not None
        assert match.group("method") == "key"

    def test_did_pattern_rejects_invalid(self, verifier):
        match = verifier._did_pattern.match("not-a-did")
        assert match is None


class TestTLSVerifierExtended:
    @pytest.fixture
    def verifier(self):
        return TLSVerifier()

    def test_extract_validity_empty(self, verifier):
        valid_from, valid_to = verifier._extract_validity({})
        assert valid_from is None
        assert valid_to is None

    def test_extract_validity_with_dates(self, verifier):
        cert = {
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }
        valid_from, valid_to = verifier._extract_validity(cert)
        assert valid_from is not None
        assert valid_to is not None

    @pytest.mark.asyncio
    async def test_verify_success_mocked(self, verifier, monkeypatch):
        mock_cert = {
            "subject": ((("CN", "example.com"),),),
            "issuer": ((("O", "Test CA"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }

        class MockSSLSocket:
            def getpeercert(self):
                return mock_cert

            def close(self):
                pass

        class MockContext:
            check_hostname = True
            verify_mode = 2

            def wrap_socket(self, sock, server_hostname=None):
                return MockSSLSocket()

        def mock_create_default_context(*args, **kwargs):
            return MockContext()

        def mock_create_connection(*args, **kwargs):
            return MockSSLSocket()

        import ssl

        monkeypatch.setattr(ssl, "create_default_context", mock_create_default_context)
        import socket as sock_mod

        monkeypatch.setattr(sock_mod, "create_connection", mock_create_connection)

        result = await verifier.verify("https://example.com", {})
        assert result.verified is True
        assert "CN=example.com" in result.subject
        assert "O=Test CA" in result.issuer
        assert result.valid_from is not None
        assert result.valid_to is not None

    @pytest.mark.asyncio
    async def test_verify_no_certificate(self, verifier, monkeypatch):
        class MockEmptySSLSocket:
            def getpeercert(self):
                return None

            def close(self):
                pass

        class MockContext:
            check_hostname = True
            verify_mode = 2

            def wrap_socket(self, sock, server_hostname=None):
                return MockEmptySSLSocket()

        def mock_create_default_context(*args, **kwargs):
            return MockContext()

        def mock_create_connection(*args, **kwargs):
            return MockEmptySSLSocket()

        import ssl

        monkeypatch.setattr(ssl, "create_default_context", mock_create_default_context)
        import socket as sock_mod

        monkeypatch.setattr(sock_mod, "create_connection", mock_create_connection)

        result = await verifier.verify("https://example.com", {})
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_empty_hostname(self, verifier):
        result = await verifier.verify("invalid://", {})
        assert result.verified is False
        assert "hostname" in result.details.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_verify_invalid_host(self, verifier):
        result = await verifier.verify("https:///path", {})
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_verify_timeout(self, verifier, monkeypatch):
        import socket

        def mock_create_connection(*args, **kwargs):
            raise TimeoutError("timed out")

        monkeypatch.setattr(socket, "create_connection", mock_create_connection)
        result = await verifier.verify("https://example.com", {})
        assert result.verified is False
        assert "timed out" in result.details.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_verify_dns_failure(self, verifier, monkeypatch):
        import socket

        def mock_create_connection(*args, **kwargs):
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "create_connection", mock_create_connection)
        result = await verifier.verify("https://nonexistent.invalid", {})
        assert result.verified is False
        assert "resolve" in result.details.get("error", "").lower()
