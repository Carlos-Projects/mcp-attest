import pytest

from mcp_attest.models import TrustLevel
from mcp_attest.trust.reputation import ReputationTracker, ServerReputation
from mcp_attest.trust.revocation import RevocationChecker
from mcp_attest.trust.scorer import TrustScorer


class TestTrustScorer:
    @pytest.fixture
    def scorer(self):
        return TrustScorer()

    def test_custom_weights(self):
        scorer = TrustScorer(
            weights={
                "identity": 0.5,
                "integrity": 0.5,
                "permission": 0.0,
                "reputation": 0.0,
            }
        )
        result = scorer.calculate(100, 0, 0, 0)
        assert result.score == 50.0

    def test_invalid_weights_raises(self):
        with pytest.raises(ValueError, match="must sum to 1.0"):
            TrustScorer(
                weights={
                    "identity": 1.0,
                    "integrity": 1.0,
                    "permission": 0.0,
                    "reputation": 0.0,
                }
            )

    def test_calculate_full_trust(self, scorer):
        result = scorer.calculate(100, 100, 100, 100)
        assert result.score == 100.0
        assert result.level == TrustLevel.FULL

    def test_calculate_zero_trust(self, scorer):
        result = scorer.calculate(0, 0, 0, 0)
        assert result.score == 0.0
        assert result.level == TrustLevel.UNTRUSTED

    def test_calculate_revoked(self, scorer):
        result = scorer.calculate(100, 100, 100, 100, revoked=True)
        assert result.score == 0.0
        assert result.revoked is True
        assert result.level == TrustLevel.UNTRUSTED

    def test_score_to_level_full(self, scorer):
        assert scorer._score_to_level(95) == TrustLevel.FULL

    def test_score_to_level_high(self, scorer):
        assert scorer._score_to_level(80) == TrustLevel.HIGH

    def test_score_to_level_medium(self, scorer):
        assert scorer._score_to_level(60) == TrustLevel.MEDIUM

    def test_score_to_level_low(self, scorer):
        assert scorer._score_to_level(30) == TrustLevel.LOW

    def test_score_to_level_untrusted(self, scorer):
        assert scorer._score_to_level(10) == TrustLevel.UNTRUSTED

    def test_score_boundary_90(self, scorer):
        assert scorer._score_to_level(90) == TrustLevel.FULL

    def test_score_boundary_70(self, scorer):
        assert scorer._score_to_level(70) == TrustLevel.HIGH

    def test_score_boundary_50(self, scorer):
        assert scorer._score_to_level(50) == TrustLevel.MEDIUM

    def test_score_boundary_25(self, scorer):
        assert scorer._score_to_level(25) == TrustLevel.LOW

    def test_weights_sum_to_one(self, scorer):
        assert abs(sum(scorer.WEIGHTS.values()) - 1.0) < 0.001

    def test_calculate_mixed_scores(self, scorer):
        result = scorer.calculate(80, 60, 90, 50)
        assert 0 < result.score < 100
        assert result.identity_score == 80
        assert result.integrity_score == 60


class TestRevocationChecker:
    @pytest.fixture
    def checker(self):
        return RevocationChecker(["https://bad.com"])

    def test_is_revoked_true(self, checker):
        assert checker.is_revoked("https://bad.com") is True

    def test_is_revoked_false(self, checker):
        assert checker.is_revoked("https://good.com") is False

    def test_add_entry(self, checker):
        checker.add("https://new-bad.com")
        assert checker.is_revoked("https://new-bad.com") is True

    def test_remove_entry(self, checker):
        checker.remove("https://bad.com")
        assert checker.is_revoked("https://bad.com") is False

    def test_remove_nonexistent(self, checker):
        checker.remove("https://nonexistent.com")
        assert checker.count == 1

    def test_count(self, checker):
        assert checker.count == 1

    def test_entries_sorted(self, checker):
        checker.add("https://aaa.com")
        assert checker.entries == ["https://aaa.com", "https://bad.com"]

    def test_fingerprint_revoked(self, checker):
        checker.add("fp123")
        assert checker.is_fingerprint_revoked("fp123") is True

    def test_empty_checker(self):
        checker = RevocationChecker()
        assert checker.count == 0
        assert checker.entries == []


class TestReputationTracker:
    @pytest.fixture
    def tracker(self):
        return ReputationTracker()

    def test_record_positive(self, tracker):
        tracker.record_attestation("https://test.com", 90.0, True)
        rep = tracker.get_reputation("https://test.com")
        assert rep is not None
        assert rep.positive_reports == 1

    def test_record_negative(self, tracker):
        tracker.record_attestation("https://test.com", 20.0, False)
        rep = tracker.get_reputation("https://test.com")
        assert rep is not None
        assert rep.negative_reports == 1

    def test_score_calculation(self, tracker):
        tracker.record_attestation("https://test.com", 80.0, True)
        tracker.record_attestation("https://test.com", 90.0, True)
        tracker.record_attestation("https://test.com", 30.0, False)
        rep = tracker.get_reputation("https://test.com")
        assert rep.positive_reports == 2
        assert rep.negative_reports == 1

    def test_get_nonexistent(self, tracker):
        assert tracker.get_reputation("https://unknown.com") is None

    def test_get_score_nonexistent(self, tracker):
        assert tracker.get_score("https://unknown.com") == 50.0

    def test_server_reputation_default_score(self):
        rep = ServerReputation(server_url="https://test.com")
        assert rep.score == 50.0

    def test_reputation_with_tags(self):
        rep = ServerReputation(
            server_url="https://test.com",
            tags=["verified", "production"],
        )
        assert "verified" in rep.tags

    def test_reputation_last_seen(self):
        rep = ServerReputation(
            server_url="https://test.com",
            last_seen="2026-05-26",
        )
        assert rep.last_seen == "2026-05-26"

    def test_reputation_score_with_reports(self):
        rep = ServerReputation(
            server_url="https://test.com",
            positive_reports=3,
            negative_reports=1,
        )
        assert rep.score == 75.0

    def test_reputation_score_all_positive(self):
        rep = ServerReputation(
            server_url="https://test.com",
            positive_reports=5,
            negative_reports=0,
        )
        assert rep.score == 100.0

    def test_reputation_score_all_negative(self):
        rep = ServerReputation(
            server_url="https://test.com",
            positive_reports=0,
            negative_reports=3,
        )
        assert rep.score == 0.0
