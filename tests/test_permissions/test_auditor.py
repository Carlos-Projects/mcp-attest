import pytest

from mcp_attest.models import (
    IdentityMethod,
    PermissionRisk,
    ServerManifest,
    ToolDeclaration,
)
from mcp_attest.permissions.auditor import PermissionAuditor
from mcp_attest.permissions.least_privilege import LeastPrivilegeChecker
from mcp_attest.permissions.policy import PolicyEvaluator


class TestPermissionAuditor:
    @pytest.fixture
    def auditor(self):
        return PermissionAuditor()

    @pytest.fixture
    def safe_manifest(self):
        return ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="read",
                    description="Read",
                    input_schema={},
                    permissions=["filesystem:read"],
                )
            ],
            identity_method="tls_cert",
        )

    @pytest.fixture
    def dangerous_manifest(self):
        return ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="exec",
                    description="Execute",
                    input_schema={},
                    permissions=["process:execute"],
                )
            ],
            identity_method="tls_cert",
        )

    @pytest.mark.asyncio
    async def test_audit_safe_manifest(self, auditor, safe_manifest):
        result = await auditor.audit(safe_manifest)
        assert result.compliant is True
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_audit_dangerous_manifest(self, auditor, dangerous_manifest):
        result = await auditor.audit(dangerous_manifest)
        assert result.compliant is False
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_audit_empty_manifest(self, auditor):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[],
            identity_method="tls_cert",
        )
        result = await auditor.audit(manifest)
        assert result.compliant is True

    def test_assess_permission_low(self, auditor):
        assert auditor._assess_permission("filesystem:read") == PermissionRisk.LOW

    def test_assess_permission_critical(self, auditor):
        assert auditor._assess_permission("process:execute") == PermissionRisk.CRITICAL

    def test_assess_permission_high(self, auditor):
        assert auditor._assess_permission("network:outbound") == PermissionRisk.HIGH

    def test_recommendation_exists(self, auditor):
        rec = auditor._recommendation("process:execute")
        assert len(rec) > 0

    def test_recommendation_default(self, auditor):
        rec = auditor._recommendation("unknown:perm")
        assert "Review" in rec

    @pytest.mark.asyncio
    async def test_audit_with_custom_permissions(self):
        auditor = PermissionAuditor(
            custom_permissions={"db:delete": "critical", "db:read": "low"}
        )
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="db_tool",
                    description="DB tool",
                    input_schema={},
                    permissions=["db:delete"],
                )
            ],
            identity_method=IdentityMethod.TLS_CERT,
        )
        result = await auditor.audit(manifest)
        assert result.compliant is False
        assert len(result.findings) == 1
        assert result.findings[0].declared_permission == "db:delete"


class TestPolicyEvaluator:
    @pytest.fixture
    def evaluator(self):
        return PolicyEvaluator(max_critical=0, max_high=2)

    def test_evaluate_safe(self, evaluator):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="read",
                    description="Read",
                    input_schema={},
                    permissions=["filesystem:read"],
                )
            ],
            identity_method="tls_cert",
        )
        compliant, violations = evaluator.evaluate(manifest)
        assert compliant is True
        assert len(violations) == 0

    def test_evaluate_critical_violation(self, evaluator):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="exec",
                    description="Exec",
                    input_schema={},
                    permissions=["process:execute"],
                )
            ],
            identity_method="tls_cert",
        )
        compliant, violations = evaluator.evaluate(manifest)
        assert compliant is False
        assert any("critical" in v.lower() for v in violations)

    def test_evaluate_disallowed_permission(self):
        evaluator = PolicyEvaluator(allowed_permissions={"filesystem:read"})
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="write",
                    description="Write",
                    input_schema={},
                    permissions=["filesystem:write"],
                )
            ],
            identity_method="tls_cert",
        )
        compliant, violations = evaluator.evaluate(manifest)
        assert compliant is False

    def test_classify_critical(self):
        assert PolicyEvaluator._classify("process:execute") == PermissionRisk.CRITICAL

    def test_classify_high(self):
        assert PolicyEvaluator._classify("filesystem:write") == PermissionRisk.HIGH

    def test_classify_low(self):
        assert PolicyEvaluator._classify("filesystem:read") == PermissionRisk.LOW

    def test_evaluate_high_count_violation(self):
        evaluator = PolicyEvaluator(max_critical=5, max_high=0)
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="writer",
                    description="Write",
                    input_schema={},
                    permissions=["filesystem:write"],
                ),
                ToolDeclaration(
                    name="networker",
                    description="Network",
                    input_schema={},
                    permissions=["network:outbound"],
                ),
            ],
            identity_method=IdentityMethod.TLS_CERT,
        )
        compliant, violations = evaluator.evaluate(manifest)
        assert compliant is False
        assert any("high" in v.lower() for v in violations)


class TestLeastPrivilegeChecker:
    def test_score_empty_manifest(self):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[],
            identity_method="tls_cert",
        )
        assert LeastPrivilegeChecker.score(manifest) == 100.0

    def test_score_safe_permissions(self):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="read",
                    description="Read",
                    input_schema={},
                    permissions=["filesystem:read"],
                )
            ],
            identity_method="tls_cert",
        )
        score = LeastPrivilegeChecker.score(manifest)
        assert score > 80.0

    def test_score_dangerous_permissions(self):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="exec",
                    description="Exec",
                    input_schema={},
                    permissions=["process:execute", "filesystem:delete"],
                )
            ],
            identity_method="tls_cert",
        )
        score = LeastPrivilegeChecker.score(manifest)
        assert score < 50.0

    def test_has_excessive_permissions_true(self):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="bad",
                    description="Bad",
                    input_schema={},
                    permissions=["process:execute", "network:raw", "secrets:write"],
                )
            ],
            identity_method="tls_cert",
        )
        assert LeastPrivilegeChecker.has_excessive_permissions(manifest) is True

    def test_has_excessive_permissions_false(self):
        manifest = ServerManifest(
            server_url="https://test.com",
            server_name="test",
            version="1.0.0",
            tools=[
                ToolDeclaration(
                    name="read",
                    description="Read",
                    input_schema={},
                    permissions=["filesystem:read"],
                )
            ],
            identity_method="tls_cert",
        )
        assert LeastPrivilegeChecker.has_excessive_permissions(manifest) is False

    def test_permission_severity_mapping(self):
        assert LeastPrivilegeChecker.PERMISSION_SEVERITY["process:execute"] == 5
        assert LeastPrivilegeChecker.PERMISSION_SEVERITY["filesystem:write"] == 3
        assert LeastPrivilegeChecker.PERMISSION_SEVERITY.get("unknown", 1) == 1
