"""
Authentication and authorization data models.
"""
from typing import Optional
from dataclasses import dataclass


@dataclass
class AuthResult:
    """
    Result of an authorization check.

    Attributes:
        allowed: Whether the request is allowed
        reason: Human-readable reason for the decision
        client_id: ID of authenticated client (if any)
        client_name: Name of authenticated client (if any)
        matched_route_id: ID of the route that was matched (if any)
    """
    allowed: bool
    reason: str
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    matched_route_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> 'AuthResult':
        """
        Create an AuthResult instance from a dictionary.

        Args:
            data: Dictionary containing auth result data

        Returns:
            AuthResult instance
        """
        return cls(
            allowed=data['allowed'],
            reason=data['reason'],
            client_id=data.get('client_id'),
            client_name=data.get('client_name'),
            matched_route_id=data.get('matched_route_id')
        )

    def to_dict(self) -> dict:
        """
        Convert to dictionary for logging/serialization.

        Returns:
            Dictionary representation of the auth result
        """
        return {
            'allowed': self.allowed,
            'reason': self.reason,
            'client_id': self.client_id,
            'client_name': self.client_name,
            'matched_route_id': self.matched_route_id
        }
