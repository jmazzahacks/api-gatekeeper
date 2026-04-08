"""Tests for client IP resolution with trusted forwarder support."""
import pytest
from unittest.mock import MagicMock
from src.utils.ip_resolver import resolve_client_ip, parse_trusted_forwarder_ips


class FakeRequest:
    """Minimal request-like object for testing IP resolution."""

    def __init__(self, headers: dict, remote_addr: str = '127.0.0.1'):
        self.headers = headers
        self.remote_addr = remote_addr


class TestResolveClientIp:
    """Tests for resolve_client_ip function."""

    def test_returns_x_real_ip_when_present(self):
        req = FakeRequest(headers={'X-Real-IP': '1.2.3.4'})
        assert resolve_client_ip(req) == '1.2.3.4'

    def test_returns_x_forwarded_for_first_entry(self):
        req = FakeRequest(headers={'X-Forwarded-For': '5.6.7.8, 10.0.0.1'})
        assert resolve_client_ip(req) == '5.6.7.8'

    def test_returns_remote_addr_as_fallback(self):
        req = FakeRequest(headers={}, remote_addr='192.168.1.1')
        assert resolve_client_ip(req) == '192.168.1.1'

    def test_returns_unknown_when_nothing_available(self):
        req = FakeRequest(headers={}, remote_addr='')
        assert resolve_client_ip(req) == 'unknown'

    def test_x_real_ip_takes_precedence_over_forwarded_for(self):
        req = FakeRequest(headers={
            'X-Real-IP': '1.1.1.1',
            'X-Forwarded-For': '2.2.2.2',
        })
        assert resolve_client_ip(req) == '1.1.1.1'

    def test_trusted_forwarder_uses_original_client_ip(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.10',
            'X-Original-Client-IP': '198.51.100.42',
        })
        trusted = {'203.0.113.10'}
        assert resolve_client_ip(req, trusted) == '198.51.100.42'

    def test_untrusted_caller_ignores_original_client_ip(self):
        req = FakeRequest(headers={
            'X-Real-IP': '99.99.99.99',
            'X-Original-Client-IP': '198.51.100.42',
        })
        trusted = {'203.0.113.10'}
        assert resolve_client_ip(req, trusted) == '99.99.99.99'

    def test_trusted_forwarder_without_original_header_falls_back(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.10',
        })
        trusted = {'203.0.113.10'}
        assert resolve_client_ip(req, trusted) == '203.0.113.10'

    def test_empty_trusted_set_ignores_original_client_ip(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.10',
            'X-Original-Client-IP': '198.51.100.42',
        })
        assert resolve_client_ip(req, set()) == '203.0.113.10'

    def test_none_trusted_set_ignores_original_client_ip(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.10',
            'X-Original-Client-IP': '198.51.100.42',
        })
        assert resolve_client_ip(req, None) == '203.0.113.10'

    def test_multiple_trusted_forwarders(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.50',
            'X-Original-Client-IP': '10.20.30.40',
        })
        trusted = {'203.0.113.10', '203.0.113.50'}
        assert resolve_client_ip(req, trusted) == '10.20.30.40'

    def test_trusted_forwarder_with_empty_original_ip_falls_back(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.10',
            'X-Original-Client-IP': '',
        })
        trusted = {'203.0.113.10'}
        assert resolve_client_ip(req, trusted) == '203.0.113.10'

    def test_trusted_forwarder_with_whitespace_original_ip_falls_back(self):
        req = FakeRequest(headers={
            'X-Real-IP': '203.0.113.10',
            'X-Original-Client-IP': '   ',
        })
        trusted = {'203.0.113.10'}
        assert resolve_client_ip(req, trusted) == '203.0.113.10'

    def test_forwarded_for_used_to_identify_trusted_forwarder(self):
        """When X-Real-IP is absent, X-Forwarded-For identifies the caller."""
        req = FakeRequest(headers={
            'X-Forwarded-For': '203.0.113.10, 10.0.0.1',
            'X-Original-Client-IP': '198.51.100.42',
        })
        trusted = {'203.0.113.10'}
        assert resolve_client_ip(req, trusted) == '198.51.100.42'


class TestParseTrustedForwarderIps:
    """Tests for parse_trusted_forwarder_ips function."""

    def test_none_returns_empty_set(self):
        assert parse_trusted_forwarder_ips(None) == set()

    def test_empty_string_returns_empty_set(self):
        assert parse_trusted_forwarder_ips('') == set()

    def test_single_ip(self):
        assert parse_trusted_forwarder_ips('1.2.3.4') == {'1.2.3.4'}

    def test_multiple_ips(self):
        result = parse_trusted_forwarder_ips('1.2.3.4,5.6.7.8')
        assert result == {'1.2.3.4', '5.6.7.8'}

    def test_whitespace_stripped(self):
        result = parse_trusted_forwarder_ips(' 1.2.3.4 , 5.6.7.8 ')
        assert result == {'1.2.3.4', '5.6.7.8'}

    def test_empty_entries_ignored(self):
        result = parse_trusted_forwarder_ips('1.2.3.4,,5.6.7.8,')
        assert result == {'1.2.3.4', '5.6.7.8'}

    def test_whitespace_only_returns_empty_set(self):
        assert parse_trusted_forwarder_ips('   ') == set()
