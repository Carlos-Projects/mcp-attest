import pytest
import respx
from httpx import Response

from mcp_attest.integrity.manifest import ManifestGenerator
from mcp_attest.utils.http import (
    check_server_reachable,
    fetch_json,
    post_json,
    validate_json_size,
    validate_url,
)


class TestValidateUrl:
    def test_valid_https_url(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_valid_http_url(self):
        assert validate_url("http://example.com:8080") == "http://example.com:8080"

    def test_invalid_scheme(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_url("ftp://example.com")

    def test_no_hostname(self):
        with pytest.raises(ValueError, match="valid hostname"):
            validate_url("https:///path")

    def test_localhost_blocked(self):
        with pytest.raises(ValueError, match="private hostname"):
            validate_url("http://localhost")

    def test_localhost_allowed_with_flag(self):
        assert (
            validate_url("http://localhost", allow_private=True) == "http://localhost"
        )

    def test_private_ipv4_blocked(self):
        with pytest.raises(ValueError, match="private IP"):
            validate_url("http://10.0.0.1")

    def test_private_ipv4_allowed(self):
        assert (
            validate_url("http://192.168.1.1", allow_private=True)
            == "http://192.168.1.1"
        )

    def test_cloud_metadata_ip_blocked(self):
        with pytest.raises(ValueError, match="private IP"):
            validate_url("http://169.254.169.254")

    def test_loopback_ipv4_blocked(self):
        with pytest.raises(ValueError, match="private IP"):
            validate_url("http://127.0.0.1")

    def test_public_ip_allowed(self):
        assert validate_url("http://93.184.216.34") == "http://93.184.216.34"


class TestValidateJsonSize:
    def test_valid_small_json(self):
        validate_json_size('{"key": "value"}')

    def test_too_large_json(self):
        large = "x" * (1024 * 1024 + 1)
        with pytest.raises(ValueError, match="too large"):
            validate_json_size(large)

    def test_too_deep_json(self):
        deep = '{"a": {' * 15 + "}" * 15 + "}" * 15
        with pytest.raises(ValueError, match="too deep"):
            validate_json_size(deep)

    def test_flat_json_valid(self):
        flat = "[" * 3 + "]" * 3
        validate_json_size(flat)


class TestManifestGeneratorHTTP:
    @pytest.mark.asyncio
    async def test_fetch_tools_success(self):
        with respx.mock:
            respx.post("https://mcp.test.com").mock(
                return_value=Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "tools": [
                                {
                                    "name": "read",
                                    "description": "Read file",
                                    "inputSchema": {"type": "object"},
                                }
                            ]
                        },
                    },
                )
            )
            gen = ManifestGenerator()
            manifest = await gen.generate("https://mcp.test.com")
            assert len(manifest.tools) == 1
            assert manifest.tools[0].name == "read"

    @pytest.mark.asyncio
    async def test_fetch_tools_empty_result(self):
        with respx.mock:
            respx.post("https://mcp.test.com").mock(
                return_value=Response(
                    200,
                    json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}},
                )
            )
            gen = ManifestGenerator()
            manifest = await gen.generate("https://mcp.test.com")
            assert len(manifest.tools) == 0

    @pytest.mark.asyncio
    async def test_fetch_tools_non_200(self):
        with respx.mock:
            respx.post("https://mcp.test.com").mock(return_value=Response(500))
            gen = ManifestGenerator()
            manifest = await gen.generate("https://mcp.test.com")
            assert len(manifest.tools) == 0


class TestHttpUtilsMocked:
    @pytest.mark.asyncio
    async def test_fetch_json_success(self):
        with respx.mock:
            respx.get("https://api.test.com/data").mock(
                return_value=Response(200, json={"key": "value"})
            )
            result = await fetch_json("https://api.test.com/data")
            assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_fetch_json_error_status(self):
        with respx.mock:
            respx.get("https://api.test.com/data").mock(return_value=Response(500))
            with pytest.raises(Exception):  # noqa: B017
                await fetch_json("https://api.test.com/data")

    @pytest.mark.asyncio
    async def test_post_json_success(self):
        with respx.mock:
            respx.post("https://api.test.com/submit").mock(
                return_value=Response(200, json={"status": "ok"})
            )
            result = await post_json("https://api.test.com/submit", {"data": "test"})
            assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_post_json_error_status(self):
        with respx.mock:
            respx.post("https://api.test.com/submit").mock(return_value=Response(400))
            with pytest.raises(Exception):  # noqa: B017
                await post_json("https://api.test.com/submit", {})

    @pytest.mark.asyncio
    async def test_check_server_reachable_200(self):
        with respx.mock:
            respx.get("https://healthy.test.com").mock(return_value=Response(200))
            result = await check_server_reachable("https://healthy.test.com")
            assert result is True

    @pytest.mark.asyncio
    async def test_check_server_reachable_404(self):
        with respx.mock:
            respx.get("https://notfound.test.com").mock(return_value=Response(404))
            result = await check_server_reachable("https://notfound.test.com")
            assert result is True

    @pytest.mark.asyncio
    async def test_check_server_reachable_500(self):
        with respx.mock:
            respx.get("https://error.test.com").mock(return_value=Response(500))
            result = await check_server_reachable("https://error.test.com")
            assert result is False
