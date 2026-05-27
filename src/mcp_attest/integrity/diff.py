"""Manifest diffing for integrity verification."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_attest.models import ServerManifest, ToolDeclaration


@dataclass
class ManifestDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)


class ManifestDiffer:
    """Compares two ServerManifests to detect changes."""

    def compare(self, expected: ServerManifest, actual: ServerManifest) -> ManifestDiff:
        expected_tools = {t.name: t for t in expected.tools}
        actual_tools = {t.name: t for t in actual.tools}

        expected_names = set(expected_tools.keys())
        actual_names = set(actual_tools.keys())

        added = sorted(actual_names - expected_names)
        removed = sorted(expected_names - actual_names)
        modified = []

        for name in sorted(expected_names & actual_names):
            if self._tools_differ(expected_tools[name], actual_tools[name]):
                modified.append(name)

        return ManifestDiff(added=added, removed=removed, modified=modified)

    @staticmethod
    def _tools_differ(t1: ToolDeclaration, t2: ToolDeclaration) -> bool:
        return (
            t1.description != t2.description
            or t1.input_schema != t2.input_schema
            or t1.permissions != t2.permissions
        )
