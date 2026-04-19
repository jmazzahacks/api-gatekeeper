"""
Tests for admin email allowlist parsing and matching.
"""
from src.utils import parse_admin_allowlist, is_email_allowed


class TestParseAdminAllowlist:
    """Tests for parse_admin_allowlist."""

    def test_none_returns_empty(self):
        assert parse_admin_allowlist(None) == frozenset()

    def test_empty_string_returns_empty(self):
        assert parse_admin_allowlist('') == frozenset()

    def test_single_email(self):
        assert parse_admin_allowlist('admin@example.com') == frozenset({'admin@example.com'})

    def test_multiple_emails(self):
        result = parse_admin_allowlist('admin@example.com,other@example.com')
        assert result == frozenset({'admin@example.com', 'other@example.com'})

    def test_whitespace_is_stripped(self):
        result = parse_admin_allowlist(' a@x.com , b@x.com ')
        assert result == frozenset({'a@x.com', 'b@x.com'})

    def test_empty_entries_are_skipped(self):
        result = parse_admin_allowlist('a@x.com,,  ,b@x.com')
        assert result == frozenset({'a@x.com', 'b@x.com'})

    def test_emails_are_lowercased(self):
        result = parse_admin_allowlist('Admin@Example.COM,USER@test.com')
        assert result == frozenset({'admin@example.com', 'user@test.com'})

    def test_duplicate_emails_collapse(self):
        result = parse_admin_allowlist('a@x.com,a@x.com,A@X.COM')
        assert result == frozenset({'a@x.com'})


class TestIsEmailAllowed:
    """Tests for is_email_allowed."""

    def test_empty_allowlist_rejects_everything(self):
        assert is_email_allowed('admin@example.com', frozenset()) is False

    def test_exact_match_allowed(self):
        allowlist = parse_admin_allowlist('admin@example.com')
        assert is_email_allowed('admin@example.com', allowlist) is True

    def test_case_insensitive_match(self):
        allowlist = parse_admin_allowlist('admin@example.com')
        assert is_email_allowed('ADMIN@Example.com', allowlist) is True

    def test_not_on_list_rejected(self):
        allowlist = parse_admin_allowlist('admin@example.com')
        assert is_email_allowed('intruder@example.com', allowlist) is False

    def test_empty_email_rejected(self):
        allowlist = parse_admin_allowlist('admin@example.com')
        assert is_email_allowed('', allowlist) is False

    def test_whitespace_in_input_is_trimmed(self):
        allowlist = parse_admin_allowlist('admin@example.com')
        assert is_email_allowed('  admin@example.com  ', allowlist) is True
