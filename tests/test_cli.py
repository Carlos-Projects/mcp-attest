import json

import pytest
from typer.testing import CliRunner

from mcp_attest.cli import app


@pytest.fixture
def runner():
    return CliRunner()


class TestCliFingerprint:
    def test_fingerprint_command(self, runner):
        result = runner.invoke(
            app,
            ["fingerprint", "--server", "https://localhost:1"],
        )
        assert result.exit_code == 0
        assert "Fingerprint:" in result.stdout

    def test_fingerprint_with_manifest(self, runner, tmp_path):
        manifest = {
            "server_url": "https://localhost:1",
            "server_name": "test",
            "version": "1.0.0",
            "tools": [],
            "identity_method": "tls_cert",
        }
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))
        result = runner.invoke(
            app,
            [
                "fingerprint",
                "--server",
                "https://localhost:1",
                "--manifest",
                str(f),
            ],
        )
        assert result.exit_code == 0
        assert "Match:" in result.stdout


class TestCliTrust:
    def test_trust_command(self, runner):
        result = runner.invoke(
            app,
            ["trust", "--server", "https://localhost:1"],
        )
        assert result.exit_code == 0
        assert "Trust Score:" in result.stdout

    def test_trust_with_revocation_list(self, runner, tmp_path):
        revocation = ["https://localhost:1"]
        f = tmp_path / "revoked.json"
        f.write_text(json.dumps(revocation))
        result = runner.invoke(
            app,
            [
                "trust",
                "--server",
                "https://localhost:1",
                "--revocation-list",
                str(f),
            ],
        )
        assert result.exit_code == 0
        assert "Revoked:" in result.stdout

    def test_trust_with_threshold(self, runner):
        result = runner.invoke(
            app,
            [
                "trust",
                "--server",
                "https://localhost:1",
                "--threshold",
                "90",
            ],
        )
        assert result.exit_code == 0
        assert "Policy:" in result.stdout


class TestCliPolicy:
    def test_policy_command(self, runner):
        result = runner.invoke(
            app,
            ["policy", "--server", "https://localhost:1"],
        )
        assert result.exit_code == 0
        assert "Policy for:" in result.stdout

    def test_policy_json_output(self, runner):
        result = runner.invoke(
            app,
            [
                "policy",
                "--server",
                "https://localhost:1",
                "--output",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "server" in data
        assert "action" in data


class TestCliGenerateManifest:
    def test_generate_manifest_command(self, runner, tmp_path):
        output = str(tmp_path / "output.json")
        result = runner.invoke(
            app,
            [
                "generate-manifest",
                "--server",
                "https://localhost:1",
                "--output",
                output,
            ],
        )
        assert result.exit_code == 0
        assert "Manifest written to" in result.stdout
        assert "Hash:" in result.stdout
        assert "Tools:" in result.stdout


class TestCliVerify:
    def test_verify_console_output(self, runner):
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--method",
                "tls_cert",
            ],
        )
        assert result.exit_code == 0

    def test_verify_json_output(self, runner):
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--method",
                "tls_cert",
                "--output",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "server_url" in data

    def test_verify_sarif_output(self, runner):
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--method",
                "tls_cert",
                "--output",
                "sarif",
            ],
        )
        assert result.exit_code == 0
        assert "$schema" in result.stdout

    def test_verify_with_identity_data(self, runner, tmp_path):
        identity = {"public_key": "test", "signature": "test"}
        f = tmp_path / "identity.json"
        f.write_text(json.dumps(identity))
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--method",
                "crypto_signature",
                "--identity-data",
                str(f),
                "--output",
                "json",
            ],
        )
        assert result.exit_code == 0

    def test_verify_with_manifest(self, runner, tmp_path):
        manifest = {
            "server_url": "https://localhost:1",
            "server_name": "test",
            "version": "1.0.0",
            "tools": [],
            "identity_method": "tls_cert",
        }
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--manifest",
                str(f),
                "--output",
                "json",
            ],
        )
        assert result.exit_code == 0

    def test_verify_with_allow_private_ips(self, runner):
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "http://localhost:1",
                "--method",
                "tls_cert",
                "--output",
                "json",
                "--allow-private-ips",
            ],
        )
        assert result.exit_code == 0

    def test_fingerprint_with_allow_private_ips(self, runner):
        result = runner.invoke(
            app,
            ["fingerprint", "--server", "http://localhost:1", "--allow-private-ips"],
        )
        assert result.exit_code == 0

    def test_trust_with_allow_private_ips(self, runner):
        result = runner.invoke(
            app,
            ["trust", "--server", "http://localhost:1", "--allow-private-ips"],
        )
        assert result.exit_code == 0

    def test_generate_manifest_nonexistent_output_dir(self, runner):
        result = runner.invoke(
            app,
            [
                "generate-manifest",
                "--server",
                "https://localhost:1",
                "--output",
                "/nonexistent_dir/output.json",
            ],
        )
        assert result.exit_code != 0

    def test_verify_nonexistent_identity_file(self, runner):
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--identity-data",
                "/nonexistent.json",
            ],
        )
        assert result.exit_code != 0

    def test_verify_nonexistent_manifest(self, runner):
        result = runner.invoke(
            app,
            [
                "verify",
                "--server",
                "https://localhost:1",
                "--manifest",
                "/nonexistent.json",
            ],
        )
        assert result.exit_code != 0
