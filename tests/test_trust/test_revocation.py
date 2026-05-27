import json

from mcp_attest.trust.revocation import RevocationChecker


class TestRevocationFileOperations:
    def test_load_from_file_list_format(self, tmp_path):
        f = tmp_path / "revoked.json"
        f.write_text(json.dumps(["https://bad1.com", "https://bad2.com"]))
        checker = RevocationChecker()
        count = checker.load_from_file(str(f))
        assert count == 2
        assert checker.is_revoked("https://bad1.com")

    def test_load_from_file_dict_format(self, tmp_path):
        f = tmp_path / "revoked.json"
        f.write_text(json.dumps({"revoked": ["https://bad.com"]}))
        checker = RevocationChecker()
        checker.load_from_file(str(f))
        assert checker.is_revoked("https://bad.com")

    def test_load_from_nonexistent_file(self):
        checker = RevocationChecker()
        count = checker.load_from_file("/nonexistent/path.json")
        assert count == 0

    def test_save_to_file(self, tmp_path):
        f = tmp_path / "output.json"
        checker = RevocationChecker(["https://bad.com"])
        checker.save_to_file(str(f))
        assert f.exists()
        data = json.loads(f.read_text())
        assert "https://bad.com" in data["revoked"]

    def test_save_and_load_roundtrip(self, tmp_path):
        f = tmp_path / "roundtrip.json"
        checker1 = RevocationChecker(["https://a.com", "https://b.com"])
        checker1.save_to_file(str(f))
        checker2 = RevocationChecker()
        checker2.load_from_file(str(f))
        assert checker2.count == 2
        assert checker2.is_revoked("https://a.com")
        assert checker2.is_revoked("https://b.com")

    def test_save_creates_parent_dirs(self, tmp_path):
        f = tmp_path / "sub" / "dir" / "revoked.json"
        checker = RevocationChecker(["https://test.com"])
        checker.save_to_file(str(f))
        assert f.exists()

    def test_entries_returns_sorted_list(self):
        checker = RevocationChecker(["https://z.com", "https://a.com", "https://m.com"])
        assert checker.entries == [
            "https://a.com",
            "https://m.com",
            "https://z.com",
        ]
