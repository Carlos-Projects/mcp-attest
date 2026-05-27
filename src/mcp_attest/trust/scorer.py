"""Trust score calculation for MCP servers."""

from __future__ import annotations

from mcp_attest.models import TrustLevel, TrustResult


class TrustScorer:
    """Calculates composite trust scores from multiple attestation signals.

    Args:
        weights: Dict with keys 'identity', 'integrity', 'permission',
            'reputation' mapping to float values that must sum to 1.0.
            Defaults to [0.30, 0.35, 0.20, 0.15].
    """

    DEFAULT_WEIGHTS = {
        "identity": 0.30,
        "integrity": 0.35,
        "permission": 0.20,
        "reputation": 0.15,
    }

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.WEIGHTS = weights or dict(self.DEFAULT_WEIGHTS)
        total = sum(self.WEIGHTS.values())
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Trust weights must sum to 1.0, got {total:.3f}")

    def calculate(
        self,
        identity_score: float,
        integrity_score: float,
        permission_score: float,
        reputation_score: float,
        revoked: bool = False,
    ) -> TrustResult:
        if revoked:
            return TrustResult(
                score=0.0,
                level=TrustLevel.UNTRUSTED,
                identity_score=identity_score,
                integrity_score=integrity_score,
                permission_score=permission_score,
                reputation_score=reputation_score,
                revoked=True,
                details={"reason": "Server is revoked"},
            )

        raw = (
            identity_score * self.WEIGHTS["identity"]
            + integrity_score * self.WEIGHTS["integrity"]
            + permission_score * self.WEIGHTS["permission"]
            + reputation_score * self.WEIGHTS["reputation"]
        )

        score = round(min(max(raw, 0.0), 100.0), 1)
        level = self._score_to_level(score)

        return TrustResult(
            score=score,
            level=level,
            identity_score=identity_score,
            integrity_score=integrity_score,
            permission_score=permission_score,
            reputation_score=reputation_score,
            revoked=False,
            details={"weights": self.WEIGHTS},
        )

    @staticmethod
    def _score_to_level(score: float) -> TrustLevel:
        if score >= 90:
            return TrustLevel.FULL
        if score >= 70:
            return TrustLevel.HIGH
        if score >= 50:
            return TrustLevel.MEDIUM
        if score >= 25:
            return TrustLevel.LOW
        return TrustLevel.UNTRUSTED
