"""
Unit tests for src/auth/aegis_tenant.py — the startup-guard validators.

Aegis phase-3 dropped integer identifiers. AEGIS_SITE_ID must now be a UUID.
This test suite locks in the validator's rejection of the pre-phase-3
integer form so a regression can't silently ship a broken config.
"""
import pytest

from src.auth import aegis_tenant


class TestAegisSiteId:
    """AEGIS_SITE_ID must be a UUID string. Anything else fails fast."""

    def test_uuid_accepted(self, monkeypatch):
        uuid_str = 'b8e9dfc0-5ba5-4bbd-a314-cb342eac0f71'
        monkeypatch.setenv('AEGIS_SITE_ID', uuid_str)
        assert aegis_tenant.aegis_site_id() == uuid_str

    def test_uppercase_uuid_accepted(self, monkeypatch):
        """Aegis canonicalises to lowercase but a config accident with an
        uppercase UUID should still parse — python's uuid.UUID() is
        case-insensitive."""
        uuid_str = 'B8E9DFC0-5BA5-4BBD-A314-CB342EAC0F71'
        monkeypatch.setenv('AEGIS_SITE_ID', uuid_str)
        assert aegis_tenant.aegis_site_id() == uuid_str

    def test_decimal_integer_rejected(self, monkeypatch):
        """The pre-phase-3 shim accepted decimal integers. Post phase-3 it
        must NOT — a leftover AEGIS_SITE_ID=5 in a stale env file would
        result in opaque 4xx responses from Aegis; failing at startup is
        the desired diagnostic."""
        monkeypatch.setenv('AEGIS_SITE_ID', '5')
        with pytest.raises(RuntimeError, match='UUID'):
            aegis_tenant.aegis_site_id()

    def test_random_garbage_rejected(self, monkeypatch):
        monkeypatch.setenv('AEGIS_SITE_ID', 'not-a-uuid')
        with pytest.raises(RuntimeError, match='UUID'):
            aegis_tenant.aegis_site_id()

    def test_empty_string_rejected(self, monkeypatch):
        monkeypatch.setenv('AEGIS_SITE_ID', '')
        with pytest.raises(RuntimeError):
            aegis_tenant.aegis_site_id()

    def test_missing_env_rejected(self, monkeypatch):
        monkeypatch.delenv('AEGIS_SITE_ID', raising=False)
        with pytest.raises(RuntimeError):
            aegis_tenant.aegis_site_id()

    def test_whitespace_only_rejected(self, monkeypatch):
        monkeypatch.setenv('AEGIS_SITE_ID', '   ')
        with pytest.raises(RuntimeError):
            aegis_tenant.aegis_site_id()
