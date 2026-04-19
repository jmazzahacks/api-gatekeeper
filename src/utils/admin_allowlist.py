"""
Parse the AEGIS_ADMIN_EMAILS allowlist from environment configuration.

Emails are compared case-insensitively. An unset or empty allowlist means
no emails are allowed to provision as admins (safe OSS default).
"""
from typing import Optional


def parse_admin_allowlist(env_value: Optional[str]) -> frozenset[str]:
    """
    Parse a comma-separated list of admin email addresses.

    Args:
        env_value: Value of AEGIS_ADMIN_EMAILS environment variable, or None

    Returns:
        Frozen set of lowercase email strings (empty if env_value is falsy)
    """
    if not env_value:
        return frozenset()
    return frozenset(
        email.strip().lower()
        for email in env_value.split(',')
        if email.strip()
    )


def is_email_allowed(email: str, allowlist: frozenset[str]) -> bool:
    """
    Check whether an email is on the admin provisioning allowlist.

    Args:
        email: Email address to check (compared case-insensitively)
        allowlist: Parsed allowlist from parse_admin_allowlist()

    Returns:
        True if email is allowed, False otherwise
    """
    if not email:
        return False
    return email.strip().lower() in allowlist
