"""
Rate limit model for per-client request limiting.
"""
from dataclasses import dataclass
import time


@dataclass
class RateLimit:
    """
    Represents a rate limit configuration for a client.

    Attributes:
        client_id: UUID of the client this limit applies to
        requests_per_day: Maximum requests allowed per 24-hour rolling window
        created_at: Unix timestamp of when the rate limit was created
        updated_at: Unix timestamp of last update
    """
    client_id: str
    requests_per_day: int  # Actually per 24 hours rolling window
    created_at: int
    updated_at: int

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        """Validate rate limit configuration."""
        if not self.client_id:
            raise ValueError("client_id is required")
        if self.requests_per_day <= 0:
            raise ValueError("requests_per_day must be positive")

    @classmethod
    def from_dict(cls, data: dict) -> 'RateLimit':
        """
        Create a RateLimit instance from a dictionary (e.g., from database).

        Args:
            data: Dictionary containing rate limit data

        Returns:
            RateLimit instance
        """
        return cls(
            client_id=str(data['client_id']),
            requests_per_day=data['requests_per_day'],
            created_at=data['created_at'],
            updated_at=data['updated_at']
        )

    def to_dict(self) -> dict:
        """
        Convert RateLimit to a dictionary.

        Returns:
            Dictionary representation of the rate limit
        """
        return {
            'client_id': self.client_id,
            'requests_per_day': self.requests_per_day,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    @classmethod
    def create_new(cls, client_id: str, requests_per_day: int) -> 'RateLimit':
        """
        Create a new rate limit with current timestamps.

        Args:
            client_id: UUID of the client
            requests_per_day: Maximum requests allowed per day

        Returns:
            New RateLimit instance
        """
        current_time = int(time.time())
        return cls(
            client_id=client_id,
            requests_per_day=requests_per_day,
            created_at=current_time,
            updated_at=current_time
        )
