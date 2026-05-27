import pytest

from mcp_attest.utils.crypto import (
    generate_key_pair,
    json_hash,
    sha256_file,
    sha256_hash,
)
from mcp_attest.utils.http import check_server_reachable, fetch_json, post_json


class TestCryptoUtils:
    def test_sha256_hash_string(self):
        h = sha256_hash("hello")
        assert len(h) == 64
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_sha256_hash_bytes(self):
        h = sha256_hash(b"hello")
        assert len(h) == 64

    def test_sha256_hash_consistent(self):
        h1 = sha256_hash("test")
        h2 = sha256_hash("test")
        assert h1 == h2

    def test_sha256_hash_different(self):
        h1 = sha256_hash("hello")
        h2 = sha256_hash("world")
        assert h1 != h2

    def test_sha256_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        h = sha256_file(str(f))
        assert len(h) == 64
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_json_hash(self):
        h = json_hash({"key": "value"})
        assert len(h) == 64

    def test_json_hash_deterministic(self):
        h1 = json_hash({"b": 1, "a": 2})
        h2 = json_hash({"a": 2, "b": 1})
        assert h1 == h2

    def test_json_hash_different(self):
        h1 = json_hash({"a": 1})
        h2 = json_hash({"a": 2})
        assert h1 != h2

    def test_generate_key_pair(self):
        private_pem, public_pem = generate_key_pair()
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem

    def test_generate_key_pair_unique(self):
        _, pub1 = generate_key_pair()
        _, pub2 = generate_key_pair()
        assert pub1 != pub2


class TestHttpUtils:
    @pytest.mark.asyncio
    async def test_check_server_reachable_unreachable(self):
        result = await check_server_reachable("https://localhost:99999", timeout=1)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_server_reachable_invalid(self):
        result = await check_server_reachable("not-a-url", timeout=1)
        assert result is False

    @pytest.mark.asyncio
    async def test_fetch_json_unreachable(self):
        with pytest.raises(Exception):  # noqa: B017
            await fetch_json("https://localhost:1", timeout=1)

    @pytest.mark.asyncio
    async def test_post_json_unreachable(self):
        with pytest.raises(Exception):  # noqa: B017
            await post_json("https://localhost:1", {}, timeout=1)
