"""
Long-lived admin API key for service-to-service admin reads.

Aegis tokens have a 1-hour TTL, which makes them unworkable for long-running
services that need to call /api/admin/* (e.g. mcp-gatekeeper). The admin API
key is a single shared secret loaded from the GATEKEEPER_ADMIN_API_KEY
environment variable on startup. Requests presenting it via the
`X-Gatekeeper-Admin-Key` header are authenticated as a `ServiceActor` —
distinct from `ConsoleAdmin` so audit logs can tell human-from-UI apart
from service-from-env-key.

Security posture: the env key is admin-equivalent if leaked. To limit
blast radius, the require_console_admin decorator only honors this key
for read-only (GET) methods. Write methods on the same endpoints still
require a real Aegis ConsoleAdmin token.
"""
import hmac
import os
from dataclasses import dataclass


# Header name used by services to present the admin API key. Distinct from
# `Authorization: Bearer …` so the decorator can tell the two auth paths
# apart without trying both validators against the same header.
ADMIN_API_KEY_HEADER = 'X-Gatekeeper-Admin-Key'

# Environment variable storing the shared secret. Loaded per request (cheap
# dict lookup) rather than cached so a rotation only needs a process restart
# at most — and a typo gets surfaced on the next request, not at startup.
ADMIN_API_KEY_ENV_VAR = 'GATEKEEPER_ADMIN_API_KEY'


@dataclass(frozen=True)
class ServiceActor:
    """Identity for an env-var admin-key caller.

    Drop-in compatible with ConsoleAdmin for `_admin_log_extra()` in
    src/blueprints/admin.py — exposes `admin_id` and `email` so audit
    log lines stay consistent, with a `service:` prefix that distinguishes
    them from real human-admin entries.
    """
    name: str

    @property
    def admin_id(self) -> str:
        return f"service:{self.name}"

    @property
    def email(self) -> str:
        return f"service:{self.name}@gatekeeper.local"


def validate_admin_api_key(provided: str) -> bool:
    """Timing-safe comparison of `provided` against the configured admin key.

    Returns False if the env var isn't set, if it's whitespace-only, if
    `provided` is empty, or if they don't match. NEVER returns True for an
    empty/whitespace configured key — that would auth any client whose
    provided header coincidentally also whitespace-collapsed to the same.
    """
    expected = os.environ.get(ADMIN_API_KEY_ENV_VAR, '').strip()
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided, expected)
