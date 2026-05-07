"""
Unit tests for the CORS allowlist parser and origin resolver.
"""
import pytest

from src.utils.cors import parse_cors_allowlist, resolve_allowed_origin


class TestParseCorsAllowlist:
    def test_none_returns_empty(self):
        assert parse_cors_allowlist(None) == frozenset()

    def test_empty_string_returns_empty(self):
        assert parse_cors_allowlist('') == frozenset()

    def test_single_origin(self):
        assert parse_cors_allowlist('https://app.example.com') == frozenset(
            {'https://app.example.com'}
        )

    def test_multiple_origins(self):
        result = parse_cors_allowlist(
            'https://a.example.com, https://b.example.com'
        )
        assert result == frozenset(
            {'https://a.example.com', 'https://b.example.com'}
        )

    def test_lowercases_scheme_and_host(self):
        assert parse_cors_allowlist('HTTPS://APP.Example.Com') == frozenset(
            {'https://app.example.com'}
        )

    def test_strips_trailing_slash_and_path(self):
        assert parse_cors_allowlist('https://app.example.com/') == frozenset(
            {'https://app.example.com'}
        )

    def test_preserves_explicit_port(self):
        assert parse_cors_allowlist('http://localhost:3000') == frozenset(
            {'http://localhost:3000'}
        )

    def test_wildcard_preserved(self):
        assert parse_cors_allowlist('*') == frozenset({'*'})

    def test_skips_blank_entries(self):
        result = parse_cors_allowlist('https://a.example.com,,  ,https://b.example.com')
        assert result == frozenset(
            {'https://a.example.com', 'https://b.example.com'}
        )


class TestResolveAllowedOrigin:
    def test_none_origin_returns_none(self):
        allowlist = frozenset({'https://app.example.com'})
        assert resolve_allowed_origin(None, allowlist) is None

    def test_empty_origin_returns_none(self):
        allowlist = frozenset({'https://app.example.com'})
        assert resolve_allowed_origin('', allowlist) is None

    def test_empty_allowlist_returns_none(self):
        # No CORS configured -> never echo back, even if origin is sent
        assert resolve_allowed_origin('https://app.example.com', frozenset()) is None

    def test_exact_match_echoes_origin(self):
        allowlist = frozenset({'https://app.example.com'})
        assert (
            resolve_allowed_origin('https://app.example.com', allowlist)
            == 'https://app.example.com'
        )

    def test_case_insensitive_match(self):
        allowlist = frozenset({'https://app.example.com'})
        # Browser sends Origin with mixed case; we echo verbatim but match case-insensitively
        assert (
            resolve_allowed_origin('HTTPS://App.Example.Com', allowlist)
            == 'HTTPS://App.Example.Com'
        )

    def test_disallowed_origin_returns_none(self):
        allowlist = frozenset({'https://app.example.com'})
        assert resolve_allowed_origin('https://evil.example.com', allowlist) is None

    def test_wildcard_echoes_any_origin(self):
        allowlist = frozenset({'*'})
        assert (
            resolve_allowed_origin('https://anywhere.example', allowlist)
            == 'https://anywhere.example'
        )

    def test_wildcard_with_no_origin_returns_none(self):
        # Even with `*`, we only echo back when the browser actually sent Origin
        assert resolve_allowed_origin(None, frozenset({'*'})) is None
