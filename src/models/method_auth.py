"""
MethodAuth model for HTTP method authentication requirements.
"""
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class AuthType(Enum):
    """Types of authentication supported."""
    API_KEY = "api_key"
    HMAC = "hmac"


@dataclass
class MethodAuth:
    """Authentication requirements for a specific HTTP method."""
    auth_required: bool
    auth_type: Optional[AuthType] = None

    def __post_init__(self) -> None:
        if self.auth_required and self.auth_type is None:
            raise ValueError("auth_type must be specified when auth_required is True")
        if not self.auth_required and self.auth_type is not None:
            raise ValueError("auth_type should be None when auth_required is False")

    @classmethod
    def from_dict(cls, data: dict) -> 'MethodAuth':
        """
        Create a MethodAuth instance from a dictionary.

        Args:
            data: Dictionary containing method auth data

        Returns:
            MethodAuth instance
        """
        auth_type = None
        if data.get('auth_type'):
            auth_type = AuthType(data['auth_type'])

        return cls(
            auth_required=data['auth_required'],
            auth_type=auth_type
        )

    def to_dict(self) -> dict:
        """
        Convert MethodAuth instance to a dictionary.

        Returns:
            Dictionary representation
        """
        return {
            'auth_required': self.auth_required,
            'auth_type': self.auth_type.value if self.auth_type else None
        }
