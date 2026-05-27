"""JSON reporter for machine-readable attestation output."""

from __future__ import annotations

import json

from mcp_attest.models import AttestationReport


class JsonReporter:
    """Formats attestation reports as JSON."""

    @staticmethod
    def render(report: AttestationReport) -> str:
        return json.dumps(report.to_dict(), indent=2, default=str)

    @staticmethod
    def render_batch(reports: list[AttestationReport]) -> str:
        return json.dumps(
            {
                "version": "1.0",
                "count": len(reports),
                "reports": [r.to_dict() for r in reports],
            },
            indent=2,
            default=str,
        )

    @staticmethod
    def parse(data: str) -> AttestationReport:
        return AttestationReport.model_validate(json.loads(data))
