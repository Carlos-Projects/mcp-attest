"""CLI for MCP Attest — Typer-based command interface."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from mcp_attest import __version__
from mcp_attest.attester import Attester
from mcp_attest.models import IdentityMethod, ServerManifest
from mcp_attest.policies.generator import PolicyGenerator
from mcp_attest.reporters.console import ConsoleReporter
from mcp_attest.reporters.json import JsonReporter
from mcp_attest.reporters.sarif import SarifReporter
from mcp_attest.utils.http import validate_json_size

app = typer.Typer(
    name="mcp-attest",
    help="Attested Tool-Server Admission for MCP",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _version_callback(
    value: bool = typer.Option(
        False, "--version", help="Show version and exit", is_eager=True
    ),
) -> None:
    """Print version and exit."""
    if value:
        from rich.console import Console as RichConsole

        RichConsole().print(f"mcp-attest v{__version__}")
        raise typer.Exit()


console = Console()


def _resolve_output_path(path: str) -> str:
    """Validate output path to prevent directory traversal."""
    p = Path(path).resolve()
    if not p.parent.exists():
        raise typer.BadParameter(f"Output directory does not exist: {p.parent}")
    return str(p)


def _load_json_file(path: str) -> Any:
    """Load and validate a JSON file with size/depth limits."""
    full_path = Path(path).resolve()
    if not full_path.exists():
        raise typer.BadParameter(f"File not found: {path}")
    if not full_path.is_file():
        raise typer.BadParameter(f"Not a file: {path}")
    content = full_path.read_text()
    validate_json_size(content)
    return json.loads(content)


@app.command()
def verify(
    server: str = typer.Option(..., "--server", "-s", help="MCP server URL"),
    manifest: str | None = typer.Option(
        None, "--manifest", "-m", help="Expected manifest JSON file"
    ),
    method: str = typer.Option(
        "tls_cert",
        "--method",
        help="Identity verification method (tls_cert, crypto_signature, did)",
    ),
    identity_data: str | None = typer.Option(
        None, "--identity-data", help="JSON file with identity data"
    ),
    output: str = typer.Option(
        "console", "--output", "-o", help="Output format (console, json, sarif)"
    ),
    allow_private_ips: bool = typer.Option(
        False, "--allow-private-ips", help="Allow connections to private IPs"
    ),
) -> None:
    """Verify MCP server identity, integrity, and trust."""
    identity_method = IdentityMethod(method)
    id_data: dict[str, Any] = {}
    if identity_data:
        id_data = _load_json_file(identity_data)

    expected_manifest: ServerManifest | None = None
    if manifest:
        manifest_data = _load_json_file(manifest)
        expected_manifest = ServerManifest.model_validate(manifest_data)

    attester = Attester(allow_private_ips=allow_private_ips)

    async def run() -> None:
        report = await attester.full_attestation(
            server_url=server,
            method=identity_method,
            identity_data=id_data,
            expected_manifest=expected_manifest,
        )

        if output == "json":
            console.print(JsonReporter.render(report))
        elif output == "sarif":
            console.print(SarifReporter.render(report))
        else:
            ConsoleReporter().render(report)

    asyncio.run(run())


@app.command()
def fingerprint(
    server: str = typer.Option(..., "--server", "-s", help="MCP server URL"),
    manifest: str | None = typer.Option(
        None, "--manifest", "-m", help="Manifest file to compare"
    ),
    allow_private_ips: bool = typer.Option(
        False, "--allow-private-ips", help="Allow connections to private IPs"
    ),
) -> None:
    """Generate capability fingerprint for an MCP server."""
    from mcp_attest.integrity.fingerprint import CapabilityFingerprinter
    from mcp_attest.integrity.manifest import ManifestGenerator

    async def run() -> None:
        gen = ManifestGenerator(allow_private=allow_private_ips)
        live = await gen.generate(server)
        fp = CapabilityFingerprinter().compute(live)

        console.print(f"Server: {server}")
        console.print(f"Fingerprint: {fp}")
        console.print(f"Tools: {len(live.tools)}")

        if manifest:
            manifest_data = _load_json_file(manifest)
            expected = ServerManifest.model_validate(manifest_data)
            expected_fp = CapabilityFingerprinter().compute(expected)
            match = fp == expected_fp
            console.print(f"Expected: {expected_fp}")
            console.print(f"Match: {'[green]YES[/]' if match else '[red]NO[/]'}")

    asyncio.run(run())


@app.command()
def trust(
    server: str = typer.Option(..., "--server", "-s", help="MCP server URL"),
    revocation_list: str | None = typer.Option(
        None, "--revocation-list", "-r", help="Revocation list JSON file"
    ),
    threshold: float = typer.Option(
        50.0, "--threshold", "-t", help="Minimum trust score"
    ),
    allow_private_ips: bool = typer.Option(
        False, "--allow-private-ips", help="Allow connections to private IPs"
    ),
) -> None:
    """Calculate trust score for an MCP server."""
    revoked: list[str] = []
    if revocation_list:
        data = _load_json_file(revocation_list)
        revoked = data if isinstance(data, list) else data.get("revoked", [])

    attester = Attester(
        revocation_list=revoked,
        trust_threshold=threshold,
        allow_private_ips=allow_private_ips,
    )

    async def run() -> None:
        identity = await attester.verify_identity(server, IdentityMethod.TLS_CERT, {})
        integrity = await attester.verify_integrity(server)
        permissions = await attester.audit_permissions(server)
        trust_result = attester.calculate_trust(
            identity, integrity, permissions, server
        )

        console.print(f"Server: {server}")
        console.print(f"Trust Score: {trust_result.score:.1f}/100")
        console.print(f"Level: {trust_result.level.value}")
        revoked_str = "[red]YES[/]" if trust_result.revoked else "[green]NO[/]"
        console.print(f"Revoked: {revoked_str}")
        policy_str = (
            "[green]allow[/]" if trust_result.score >= threshold else "[red]deny[/]"
        )
        console.print(f"Policy: {policy_str}")

    asyncio.run(run())


@app.command()
def policy(
    server: str = typer.Option(..., "--server", "-s", help="MCP server URL"),
    min_score: float = typer.Option(
        75.0, "--min-score", help="Minimum trust score for allow"
    ),
    output: str = typer.Option(
        "console", "--output", "-o", help="Output format (console, json)"
    ),
    allow_private_ips: bool = typer.Option(
        False, "--allow-private-ips", help="Allow connections to private IPs"
    ),
) -> None:
    """Generate MCPGuard access policy for an MCP server."""
    attester = Attester(
        trust_threshold=min_score,
        allow_private_ips=allow_private_ips,
    )

    async def run() -> None:
        identity = await attester.verify_identity(server, IdentityMethod.TLS_CERT, {})
        integrity = await attester.verify_integrity(server)
        permissions = await attester.audit_permissions(server)
        trust_result = attester.calculate_trust(
            identity, integrity, permissions, server
        )

        from mcp_attest.models import AttestationReport

        report = AttestationReport(
            server_url=server,
            identity=identity,
            integrity=integrity,
            permissions=permissions,
            trust=trust_result,
        )

        policy_json = PolicyGenerator.generate_json(report)

        if output == "json":
            console.print(policy_json)
        else:
            console.print(f"Policy for: {server}")
            console.print(policy_json)

    asyncio.run(run())


@app.command()
def generate_manifest(
    server: str = typer.Option(..., "--server", "-s", help="MCP server URL"),
    output: str = typer.Option(
        "manifest.json", "--output", "-o", help="Output file path"
    ),
    allow_private_ips: bool = typer.Option(
        False, "--allow-private-ips", help="Allow connections to private IPs"
    ),
) -> None:
    """Generate a manifest from a live MCP server."""
    from mcp_attest.integrity.manifest import ManifestGenerator

    output_path = _resolve_output_path(output)

    async def run() -> None:
        gen = ManifestGenerator(allow_private=allow_private_ips)
        manifest = await gen.generate(server)
        manifest.compute_hash()

        with open(output_path, "w") as f:
            json.dump(manifest.model_dump(mode="json"), f, indent=2, default=str)

        console.print(f"Manifest written to {output_path}")
        console.print(f"Hash: {manifest.manifest_hash}")
        console.print(f"Tools: {len(manifest.tools)}")

    asyncio.run(run())


if __name__ == "__main__":
    app()
