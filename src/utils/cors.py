"""
Parse the CORS_ALLOWED_ORIGINS allowlist and resolve the Allow-Origin header.

The allowlist is a comma-separated list of origins (e.g. https://app.example.com).
A single literal "*" entry means "echo any origin" — only safe in dev.

Origins are compared case-insensitively for the scheme/host portion. The path,
fragment, and trailing slash on the request's Origin header are ignored — only
the scheme://host[:port] tuple matters per the CORS spec.
"""
from typing import Optional
from urllib.parse import urlparse


def parse_cors_allowlist(env_value: Optional[str]) -> frozenset[str]:
    """
    Parse a comma-separated list of allowed origins.

    Args:
        env_value: Value of CORS_ALLOWED_ORIGINS env var, or None

    Returns:
        Frozen set of normalized origin strings (empty if env_value is falsy).
        The literal entry "*" is preserved verbatim and means "any origin".
    """
    if not env_value:
        return frozenset()
    return frozenset(
        _normalize_origin(entry)
        for entry in env_value.split(',')
        if entry.strip()
    )


def resolve_allowed_origin(
    request_origin: Optional[str],
    allowlist: frozenset[str]
) -> Optional[str]:
    """
    Resolve the value to put in Access-Control-Allow-Origin.

    Args:
        request_origin: Value of the browser's Origin header (or None)
        allowlist: Parsed allowlist from parse_cors_allowlist()

    Returns:
        The origin string to echo back, or None if the origin is not allowed
        (caller should omit CORS headers in that case, which causes the browser
        to drop the response — the correct behavior for a non-allowlisted origin).
    """
    if not request_origin or not allowlist:
        return None
    if '*' in allowlist:
        return request_origin
    normalized = _normalize_origin(request_origin)
    if normalized in allowlist:
        return request_origin
    return None


def _normalize_origin(value: str) -> str:
    """
    Reduce an origin string to its canonical scheme://host[:port] form, lowercase.

    Handles both bare origins ("https://api.example.com") and stray paths/slashes
    ("https://api.example.com/"); strips anything after the host:port.
    """
    raw = value.strip()
    if raw == '*':
        return '*'
    parsed = urlparse(raw)
    # If the input lacked a scheme, urlparse puts everything in `path`.
    # Treat that as malformed and return the lowercased input — it won't match
    # a properly-configured allowlist entry, which is the correct outcome.
    if not parsed.scheme or not parsed.netloc:
        return raw.lower()
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
