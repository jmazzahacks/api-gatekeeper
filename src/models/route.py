"""
Route model for endpoint authentication and authorization.
"""
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum
import time

from .method_auth import MethodAuth


class HttpMethod(Enum):
    """HTTP methods supported for route configuration."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class Route:
    """
    Represents a protected API route with method-specific authentication requirements.

    Attributes:
        route_id: Unique identifier for the route (auto-generated if None)
        route_pattern: URL pattern (exact match or wildcard with /*)
        domain: Domain for route matching (exact, wildcard like *.example.com, or * for any)
        service_name: Name of the backend service this route protects
        methods: Dictionary mapping HTTP methods to their auth requirements
        created_at: Unix timestamp of when the route was created
        updated_at: Unix timestamp of last update
    """
    route_pattern: str
    domain: str
    service_name: str
    methods: Dict[HttpMethod, MethodAuth]
    created_at: int
    updated_at: int
    route_id: Optional[str] = None

    def __post_init__(self) -> None:
        self._validate_route_pattern()
        self._validate_domain()
        self._validate_methods()

    def _validate_route_pattern(self) -> None:
        """Validate that the route pattern is properly formatted."""
        if not self.route_pattern.startswith('/'):
            raise ValueError("route_pattern must start with /")

        # Check for wildcard - should only be at the end as /*
        if '*' in self.route_pattern:
            if not self.route_pattern.endswith('/*'):
                raise ValueError("Wildcard * must only appear at the end as /*")
            if self.route_pattern.count('*') > 1:
                raise ValueError("Only one wildcard is allowed per route pattern")

    def _validate_domain(self) -> None:
        """Validate that the domain is properly formatted."""
        import re

        if not self.domain:
            raise ValueError("domain is required")

        # Domain validation regex: matches *, *.example.com, example.com, sub.example.com
        # Allows alphanumeric, hyphens, and dots
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$|^\*$|^\*\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'

        if not re.match(domain_pattern, self.domain):
            raise ValueError(
                "domain must be a valid format: 'example.com', '*.example.com', or '*' for any domain"
            )

    def _validate_methods(self) -> None:
        """Validate that at least one method is defined."""
        if not self.methods:
            raise ValueError("At least one HTTP method must be defined")

    def matches(self, path: str) -> bool:
        """
        Check if a given path matches this route pattern.

        Args:
            path: The URL path to check

        Returns:
            True if the path matches this route pattern
        """
        if self.route_pattern.endswith('/*'):
            # Wildcard match - check if path starts with the prefix
            prefix = self.route_pattern[:-2]  # Remove /*
            return path.startswith(prefix)
        else:
            # Exact match
            return path == self.route_pattern

    def matches_domain(self, domain: Optional[str]) -> bool:
        """
        Check if a given domain matches this route's domain pattern.

        Args:
            domain: The domain to check (case-insensitive)

        Returns:
            True if the domain matches this route's domain pattern
        """
        if not domain:
            # No domain provided, only match if route domain is *
            return self.domain == '*'

        # Case-insensitive comparison
        domain_lower = domain.lower()
        route_domain_lower = self.domain.lower()

        # Exact wildcard match (any domain)
        if route_domain_lower == '*':
            return True

        # Subdomain wildcard match (e.g., *.example.com)
        if route_domain_lower.startswith('*.'):
            base_domain = route_domain_lower[2:]  # Remove *.
            # Check if domain ends with .base_domain or equals base_domain
            return domain_lower == base_domain or domain_lower.endswith('.' + base_domain)

        # Exact domain match
        return domain_lower == route_domain_lower

    def get_auth_requirements(self, method: HttpMethod) -> Optional[MethodAuth]:
        """
        Get authentication requirements for a specific HTTP method.

        Args:
            method: The HTTP method to check

        Returns:
            MethodAuth object if the method is configured, None otherwise
        """
        return self.methods.get(method)

    def requires_auth(self, method: HttpMethod) -> bool:
        """
        Check if authentication is required for a specific method.

        Args:
            method: The HTTP method to check

        Returns:
            True if authentication is required, False otherwise
        """
        method_auth = self.get_auth_requirements(method)
        return method_auth.auth_required if method_auth else False

    @classmethod
    def from_dict(cls, data: dict) -> 'Route':
        """
        Create a Route instance from a dictionary (e.g., from database).

        Args:
            data: Dictionary containing route data

        Returns:
            Route instance
        """
        # Convert methods dict to MethodAuth objects
        methods = {}
        for method_str, auth_config in data.get('methods', {}).items():
            method = HttpMethod(method_str)
            methods[method] = MethodAuth.from_dict(auth_config)

        return cls(
            route_id=data['route_id'],
            route_pattern=data['route_pattern'],
            domain=data['domain'],
            service_name=data['service_name'],
            methods=methods,
            created_at=data['created_at'],
            updated_at=data['updated_at']
        )

    def to_dict(self) -> dict:
        """
        Convert Route instance to a dictionary for storage.

        Returns:
            Dictionary representation of the route
        """
        methods_dict = {}
        for method, auth in self.methods.items():
            methods_dict[method.value] = auth.to_dict()

        return {
            'route_id': self.route_id,
            'route_pattern': self.route_pattern,
            'domain': self.domain,
            'service_name': self.service_name,
            'methods': methods_dict,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    @classmethod
    def create_new(
        cls,
        route_pattern: str,
        domain: str,
        service_name: str,
        methods: Dict[HttpMethod, MethodAuth],
        route_id: Optional[str] = None
    ) -> 'Route':
        """
        Create a new Route with current timestamp.

        Args:
            route_pattern: URL pattern
            domain: Domain for route matching
            service_name: Backend service name
            methods: Method authentication configurations
            route_id: Optional unique identifier (auto-generated by database if None)

        Returns:
            New Route instance
        """
        now = int(time.time())
        return cls(
            route_pattern=route_pattern,
            domain=domain,
            service_name=service_name,
            methods=methods,
            created_at=now,
            updated_at=now,
            route_id=route_id
        )
