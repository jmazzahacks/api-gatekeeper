"""Aegis tenant-key client.

Singleton AegisClient configured with the per-tenant API key, used to proxy
the six gated public auth endpoints (register, login, verify-email,
check-verification-token, request-password-reset, reset-password). The key
is auto-attached as `X-Tenant-Api-Key` on every request.

NAMING GOTCHA: "tenant" in `AEGIS_TENANT_API_KEY` is *Aegis*'s term for "the
backend product integrating with Aegis" — i.e., this api-gatekeeper backend.
There is exactly one such key for the entire deployment. Never browser-side.

Bearer-gated endpoints (/me, change-password, logout, refresh,
confirm-email-change) do NOT use this client — the browser calls Aegis
directly with the user's session bearer for those.
"""
import os
import uuid as uuid_mod
from typing import Optional

from byteforge_aegis_client import AegisClient, AegisClientConfig


_tenant_client: Optional[AegisClient] = None


def _required_env(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if not value:
        raise RuntimeError(
            f"{name} is not configured (env var is missing or empty); "
            f"the Aegis auth proxy cannot serve /api/auth/* requests"
        )
    return value


def aegis_api_url() -> str:
    return _required_env('AEGIS_API_URL')


def aegis_site_id() -> str:
    """
    Return the configured Aegis site identifier as a validated string.

    Accepts either the legacy integer id (as a decimal string) or the UUID
    string form. The Aegis API accepts both during the int->UUID shim; the
    client library types this as `Identifier = Union[int, str]`. We validate
    at the config layer so a typo (e.g. AEGIS_SITE_ID=fivve) fails fast at
    startup rather than surfacing later as an opaque 4xx from Aegis.
    """
    raw = _required_env('AEGIS_SITE_ID')
    if raw.isdigit():
        return raw
    try:
        uuid_mod.UUID(raw)
    except ValueError:
        raise RuntimeError(
            f"AEGIS_SITE_ID must be a decimal integer or UUID, got {raw!r}"
        )
    return raw


def aegis_tenant_api_key() -> str:
    return _required_env('AEGIS_TENANT_API_KEY')


def aegis_tenant_client() -> AegisClient:
    """Singleton client configured with the Aegis tenant API key."""
    global _tenant_client
    if _tenant_client is None:
        _tenant_client = AegisClient(AegisClientConfig(
            api_url=aegis_api_url(),
            site_id=aegis_site_id(),
            tenant_api_key=aegis_tenant_api_key(),
        ))
    return _tenant_client


def reset_tenant_client() -> None:
    """Test seam — drop the singleton so the next call rebuilds it."""
    global _tenant_client
    _tenant_client = None
