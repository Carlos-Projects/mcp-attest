"""Manifest generation from live MCP servers."""

from __future__ import annotations

import json
from typing import Any

import httpx

from mcp_attest.models import IdentityMethod, ServerManifest, ToolDeclaration
from mcp_attest.utils.http import validate_json_size, validate_url


class ManifestGenerator:
    """Generates a ServerManifest by querying an MCP server's tool list."""

    def __init__(self, allow_private: bool = False) -> None:
        self.allow_private = allow_private

    async def generate(self, server_url: str) -> ServerManifest:
        tools = await self._fetch_tools(server_url)
        return ServerManifest(
            server_url=server_url,
            server_name=self._extract_name(server_url),
            version="0.0.0",
            tools=tools,
            identity_method=IdentityMethod.TLS_CERT,
        )

    async def _fetch_tools(self, server_url: str) -> list[ToolDeclaration]:
        try:
            validate_url(server_url, allow_private=self.allow_private)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    server_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {},
                    },
                )
                if resp.status_code != 200:
                    return []
                body = resp.text
                validate_json_size(body)
                data = resp.json()
                result = data.get("result", {})
                tools_data = result.get("tools", [])
                return [ManifestGenerator._parse_tool(t) for t in tools_data]
        except Exception:
            return []

    @staticmethod
    def _parse_tool(tool_data: dict[str, Any]) -> ToolDeclaration:
        return ToolDeclaration(
            name=tool_data.get("name", "unknown"),
            description=tool_data.get("description", ""),
            input_schema=tool_data.get("inputSchema", {}),
        )

    @staticmethod
    def _extract_name(url: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.hostname or url

    @staticmethod
    def generate_from_dict(data: dict[str, Any]) -> ServerManifest:
        return ServerManifest.model_validate(data)

    @staticmethod
    def generate_from_file(path: str) -> ServerManifest:
        with open(path) as f:
            content = f.read()
            validate_json_size(content)
            return ManifestGenerator.generate_from_dict(json.loads(content))
