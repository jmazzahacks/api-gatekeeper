"""
Client IP resolution with trusted forwarder support.

When the gatekeeper sits behind Cloudflare and upstream servers make auth
subrequests through Cloudflare, the real client IP gets lost — Cloudflare
sets CF-Connecting-IP to the upstream server's IP, not the original client.

To solve this, upstream servers can forward the real client IP in an
X-Original-Client-IP header. The gatekeeper trusts this header only when
the immediate caller (identified by X-Real-IP) is in the trusted forwarder
list, preventing spoofing by arbitrary clients.
"""
import logging
from typing import Optional

from flask import Request

logger = logging.getLogger(__name__)


def resolve_client_ip(
    request: Request,
    trusted_forwarder_ips: Optional[set[str]] = None
) -> str:
    """
    Resolve the real client IP from the request, accounting for trusted forwarders.

    Resolution order:
    1. If the caller IP is a trusted forwarder and X-Original-Client-IP is present,
       use X-Original-Client-IP (the real client behind the forwarder).
    2. X-Real-IP header (set by nginx from $remote_addr after Cloudflare resolution).
    3. First entry in X-Forwarded-For header.
    4. Flask's request.remote_addr.
    5. 'unknown' as fallback.

    Args:
        request: The Flask request object.
        trusted_forwarder_ips: Set of IPs that are trusted to forward X-Original-Client-IP.

    Returns:
        The resolved client IP address.
    """
    caller_ip = (
        request.headers.get('X-Real-IP')
        or request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        or request.remote_addr
        or ''
    )

    if trusted_forwarder_ips and caller_ip in trusted_forwarder_ips:
        original_client_ip = request.headers.get('X-Original-Client-IP', '').strip()
        if original_client_ip:
            logger.debug(
                "Using forwarded client IP from trusted forwarder",
                extra={
                    'forwarder_ip': caller_ip,
                    'original_client_ip': original_client_ip,
                }
            )
            return original_client_ip

    return caller_ip or 'unknown'


def parse_trusted_forwarder_ips(env_value: Optional[str]) -> set[str]:
    """
    Parse a comma-separated list of trusted forwarder IPs from an env var.

    Args:
        env_value: Comma-separated IP addresses, or None/empty.

    Returns:
        Set of IP address strings (empty set if no value provided).
    """
    if not env_value:
        return set()

    ips = set()
    for ip in env_value.split(','):
        stripped = ip.strip()
        if stripped:
            ips.add(stripped)

    return ips
