import json

import pytest

from mcp_attest.integrity.diff import ManifestDiffer
from mcp_attest.integrity.fingerprint import CapabilityFingerprinter
from mcp_attest.integrity.manifest import ManifestGenerator
from mcp_attest.models import ServerManifest, ToolDeclaration


class TestManifestGenerator:
    @pytest.fixture
    def generator(self):
        return ManifestGenerator()

    @pytest.mark.asyncio
    async def test_generate_unreachable_server(self, generator):
        manifest = await generator.generate("https://localhost:1")
        assert manifest.server_url == "https://localhost:1"
        assert len(manifest.tools) == 0

    def test_generate_from_dict(self, generator):
        data = {
            "server_url": "https://test.com",
            "server_name": "test",
            "version": "1.0.0",
            "tools": [],
            "identity_method": "tls_cert",
        }
        manifest = generator.generate_from_dict(data)
        assert manifest.server_name == "test"
        assert manifest.version == "1.0.0"

    def test_generate_from_dict_with_tools(self, generator):
        data = {
            "server_url": "https://test.com",
            "server_name": "test",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "tool1",
                    "description": "desc",
                    "input_schema": {},
                    "permissions": [],
                }
            ],
            "identity_method": "tls_cert",
        }
        manifest = generator.generate_from_dict(data)
        assert len(manifest.tools) == 1
        assert manifest.tools[0].name == "tool1"

    def test_extract_name_from_url(self, generator):
        url1 = "https://mcp.example.com/api"
        assert generator._extract_name(url1) == "mcp.example.com"
        assert generator._extract_name("http://localhost:3000") == "localhost"

    def test_generate_from_file(self, generator, tmp_path):
        data = {
            "server_url": "https://test.com",
            "server_name": "test",
            "version": "1.0.0",
            "tools": [],
            "identity_method": "tls_cert",
        }
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(data))
        manifest = generator.generate_from_file(str(f))
        assert manifest.server_name == "test"

    def test_parse_tool_minimal(self, generator):
        tool = generator._parse_tool({"name": "test"})
        assert tool.name == "test"
        assert tool.description == ""
        assert tool.input_schema == {}

    def test_parse_tool_full(self, generator):
        tool = generator._parse_tool(
            {
                "name": "read",
                "description": "Read file",
                "inputSchema": {"type": "object"},
            }
        )
        assert tool.name == "read"
        assert tool.description == "Read file"
        assert tool.input_schema == {"type": "object"}


class TestCapabilityFingerprinter:
    @pytest.fixture
    def fingerprinter(self):
        return CapabilityFingerprinter()

    def test_compute_fingerprint(self, fingerprinter):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(name="tool1", description="desc", input_schema={}),
            ],
            identity_method="tls_cert",
        )
        fp = fingerprinter.compute(manifest)
        assert len(fp) == 64

    def test_compute_fingerprint_deterministic(self, fingerprinter):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(name="tool1", description="desc", input_schema={}),
            ],
            identity_method="tls_cert",
        )
        fp1 = fingerprinter.compute(manifest)
        fp2 = fingerprinter.compute(manifest)
        assert fp1 == fp2

    def test_compute_fingerprint_different_tools(self, fingerprinter):
        m1 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[ToolDeclaration(name="a", description="d", input_schema={})],
            identity_method="tls_cert",
        )
        m2 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[ToolDeclaration(name="b", description="d", input_schema={})],
            identity_method="tls_cert",
        )
        assert fingerprinter.compute(m1) != fingerprinter.compute(m2)

    def test_compare_matching(self, fingerprinter):
        assert CapabilityFingerprinter.compare("abc", "abc") is True

    def test_compare_not_matching(self, fingerprinter):
        assert CapabilityFingerprinter.compare("abc", "def") is False

    def test_tool_signature_stable(self, fingerprinter):
        tool = ToolDeclaration(name="t", description="d", input_schema={"k": "v"})
        sig1 = fingerprinter._tool_signature(tool)
        sig2 = fingerprinter._tool_signature(tool)
        assert sig1 == sig2


class TestManifestDiffer:
    @pytest.fixture
    def differ(self):
        return ManifestDiffer()

    def test_no_changes(self, differ):
        tools = [ToolDeclaration(name="t1", description="d", input_schema={})]
        m1 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=tools,
            identity_method="tls_cert",
        )
        m2 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=tools,
            identity_method="tls_cert",
        )
        diff = differ.compare(m1, m2)
        assert not diff.has_changes()
        assert diff.added == []
        assert diff.removed == []
        assert diff.modified == []

    def test_added_tool(self, differ):
        m1 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[],
            identity_method="tls_cert",
        )
        m2 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[ToolDeclaration(name="new", description="d", input_schema={})],
            identity_method="tls_cert",
        )
        diff = differ.compare(m1, m2)
        assert diff.added == ["new"]
        assert diff.has_changes()

    def test_removed_tool(self, differ):
        m1 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[ToolDeclaration(name="old", description="d", input_schema={})],
            identity_method="tls_cert",
        )
        m2 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[],
            identity_method="tls_cert",
        )
        diff = differ.compare(m1, m2)
        assert diff.removed == ["old"]
        assert diff.has_changes()

    def test_modified_tool(self, differ):
        t1 = ToolDeclaration(name="t", description="old", input_schema={})
        t2 = ToolDeclaration(name="t", description="new", input_schema={})
        m1 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[t1],
            identity_method="tls_cert",
        )
        m2 = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[t2],
            identity_method="tls_cert",
        )
        diff = differ.compare(m1, m2)
        assert diff.modified == ["t"]
        assert diff.has_changes()

    def test_tools_differ_description(self, differ):
        t1 = ToolDeclaration(name="t", description="a", input_schema={})
        t2 = ToolDeclaration(name="t", description="b", input_schema={})
        assert differ._tools_differ(t1, t2) is True

    def test_tools_differ_schema(self, differ):
        t1 = ToolDeclaration(name="t", description="d", input_schema={"a": 1})
        t2 = ToolDeclaration(name="t", description="d", input_schema={"a": 2})
        assert differ._tools_differ(t1, t2) is True

    def test_tools_differ_permissions(self, differ):
        t1 = ToolDeclaration(
            name="t", description="d", input_schema={}, permissions=["p1"]
        )
        t2 = ToolDeclaration(
            name="t", description="d", input_schema={}, permissions=["p2"]
        )
        assert differ._tools_differ(t1, t2) is True

    def test_tools_not_differ(self, differ):
        t = ToolDeclaration(name="t", description="d", input_schema={})
        assert differ._tools_differ(t, t) is False
