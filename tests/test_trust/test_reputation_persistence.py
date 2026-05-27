"""Tests for SQLite-backed reputation persistence."""

import tempfile

import pytest

from mcp_attest.trust.reputation import ReputationTracker, ServerReputation


class TestReputationPersistence:
    def test_memory_only_no_db(self):
        tracker = ReputationTracker()
        assert tracker._db_path is None
        tracker.record_attestation("https://test.com", 90.0, True)
        assert tracker.get_score("https://test.com") == 100.0

    def test_db_creates_table(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            tracker = ReputationTracker(db_path=f.name)
            cursor = tracker._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = [row[0] for row in cursor.fetchall()]
            assert "reputation" in tables
            tracker.close()

    def test_persists_across_sessions(self):
        url = "https://test.com"
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            db_path = f.name
            tracker1 = ReputationTracker(db_path=db_path)
            tracker1.record_attestation(url, 90.0, True)
            tracker1.record_attestation(url, 80.0, True)
            tracker1.record_attestation(url, 20.0, False)
            tracker1.close()

            tracker2 = ReputationTracker(db_path=db_path)
            rep = tracker2.get_reputation(url)
            assert rep is not None
            assert rep.positive_reports == 2
            assert rep.negative_reports == 1
            assert rep.avg_trust_score == pytest.approx(63.3, 0.1)
            tracker2.close()

    def test_tags_persisted(self):
        url = "https://test.com"
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            db_path = f.name
            tracker1 = ReputationTracker(db_path=db_path)
            rep = ServerReputation(server_url=url, positive_reports=1)
            rep.tags = ["verified", "production"]
            tracker1._servers[url] = rep
            tracker1._save(url)
            tracker1.close()

            tracker2 = ReputationTracker(db_path=db_path)
            loaded = tracker2.get_reputation(url)
            assert loaded is not None
            assert "verified" in loaded.tags
            assert "production" in loaded.tags
            tracker2.close()

    def test_last_seen_updated(self):
        url = "https://test.com"
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            db_path = f.name
            tracker = ReputationTracker(db_path=db_path)
            tracker.record_attestation(url, 90.0, True)
            rep = tracker.get_reputation(url)
            assert rep is not None
            assert len(rep.last_seen) > 0
            assert "T" in rep.last_seen
            tracker.close()

    def test_isolated_servers(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            db_path = f.name
            tracker = ReputationTracker(db_path=db_path)
            tracker.record_attestation("https://a.com", 90.0, True)
            tracker.record_attestation("https://b.com", 10.0, False)
            assert tracker.get_score("https://a.com") == 100.0
            assert tracker.get_score("https://b.com") == 0.0
            tracker.close()
