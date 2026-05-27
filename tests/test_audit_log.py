"""Tests for audit logging."""

import json
import tempfile

from mcp_attest.models import (
    AttestationReport,
    IdentityMethod,
    IdentityResult,
    IntegrityResult,
    IntegrityStatus,
    PermissionFinding,
    PermissionResult,
    PermissionRisk,
    TrustLevel,
    TrustResult,
)
from mcp_attest.utils.audit import AuditLogger


def _make_report(server_url: str = "https://test.com") -> AttestationReport:
    return AttestationReport(
        server_url=server_url,
        identity=IdentityResult(
            verified=True,
            method=IdentityMethod.TLS_CERT,
            subject=server_url,
            issuer="test-ca",
        ),
        integrity=IntegrityResult(
            status=IntegrityStatus.VERIFIED,
            manifest_hash="abc123",
            fingerprint="fp123",
        ),
        permissions=PermissionResult(
            compliant=False,
            least_privilege_score=85.0,
            findings=[
                PermissionFinding(
                    tool_name="file_server",
                    declared_permission="read",
                    actual_permission="write",
                    risk=PermissionRisk.CRITICAL,
                    recommendation="Reduce to read-only",
                )
            ],
        ),
        trust=TrustResult(
            score=92.5,
            level=TrustLevel.FULL,
            identity_score=85.0,
            integrity_score=100.0,
            permission_score=85.0,
            reputation_score=50.0,
            revoked=False,
            details={"weights": {"identity": 0.3}},
        ),
        policy_recommended="allow",
    )


class TestAuditLogger:
    def test_no_log_path_does_nothing(self):
        logger = AuditLogger()
        report = _make_report()
        logger.log_attestation(report)

    def test_logs_to_file(self):
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl") as f:
            logger = AuditLogger(log_path=f.name)
            report = _make_report()
            logger.log_attestation(report)
            line = f.readline()
            entry = json.loads(line)
            assert entry["server_url"] == "https://test.com"
            assert entry["identity"]["verified"] is True
            assert entry["trust"]["score"] == 92.5
            assert entry["policy_recommended"] == "allow"

    def test_appends_multiple_entries(self):
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl") as f:
            logger = AuditLogger(log_path=f.name)
            logger.log_attestation(_make_report("https://a.com"))
            logger.log_attestation(_make_report("https://b.com"))
            lines = f.readlines()
            assert len(lines) == 2
            assert json.loads(lines[0])["server_url"] == "https://a.com"
            assert json.loads(lines[1])["server_url"] == "https://b.com"

    def test_entry_structure(self):
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl") as f:
            logger = AuditLogger(log_path=f.name)
            logger.log_attestation(_make_report())
            entry = json.loads(f.readline())
            assert "timestamp" in entry
            assert "server_url" in entry
            assert "identity" in entry
            assert "integrity" in entry
            assert "permissions" in entry
            assert "trust" in entry
            assert "policy_recommended" in entry
