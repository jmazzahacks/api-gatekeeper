#!/usr/bin/env python
"""
Interactive script to create a new client in the API auth service.

Usage:
  python scripts/create_client.py
"""

import sys
import secrets
from dotenv import load_dotenv

from src.utils import get_db_connection
from src.models.client import Client, ClientStatus


def get_input(prompt: str, default: str = None) -> str:
    """Get user input with optional default value."""
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "

    value = input(prompt).strip()
    if not value and default:
        return default
    return value


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no input from user."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{prompt} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ['y', 'yes']


def get_choice(prompt: str, choices: list, default: str = None) -> str:
    """Get a choice from a list of options."""
    print(f"\n{prompt}")
    for i, choice in enumerate(choices, 1):
        print(f"  {i}. {choice}")

    while True:
        if default:
            response = input(f"Enter choice (1-{len(choices)}) [{default}]: ").strip()
        else:
            response = input(f"Enter choice (1-{len(choices)}): ").strip()

        if not response and default:
            return default

        try:
            idx = int(response) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass

        print(f"Invalid choice. Please enter a number between 1 and {len(choices)}")


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return secrets.token_urlsafe(32)


def generate_shared_secret() -> str:
    """Generate a secure random shared secret."""
    return secrets.token_urlsafe(32)


def main():
    """Main function to create a client."""
    load_dotenv()

    print("=" * 60)
    print("Create New API Client")
    print("=" * 60)

    # Get client name
    client_name = get_input("Client name (e.g., 'Mobile App v2.1')")
    if not client_name:
        print("Error: Client name is required")
        sys.exit(1)

    # Ask about credentials
    print("\n" + "=" * 60)
    print("Credential Configuration")
    print("=" * 60)
    print("\nClients need at least one credential type:")
    print("  - API Key: Simple authentication, good for less sensitive operations")
    print("  - Shared Secret: For HMAC signatures, more secure")
    print("  - Both: Use different auth methods for different scenarios")

    use_api_key = get_yes_no("\nGenerate API key?", default=True)
    use_shared_secret = get_yes_no("Generate shared secret for HMAC?", default=False)

    if not use_api_key and not use_shared_secret:
        print("\nError: Client must have at least one credential type")
        sys.exit(1)

    # Generate credentials
    api_key = None
    shared_secret = None

    if use_api_key:
        if get_yes_no("\nProvide custom API key?", default=False):
            api_key = get_input("API key")
            if not api_key:
                print("Error: API key cannot be empty if provided")
                sys.exit(1)
        else:
            api_key = generate_api_key()
            print(f"Generated API key: {api_key}")

    if use_shared_secret:
        if get_yes_no("\nProvide custom shared secret?", default=False):
            shared_secret = get_input("Shared secret")
            if not shared_secret:
                print("Error: Shared secret cannot be empty if provided")
                sys.exit(1)
        else:
            shared_secret = generate_shared_secret()
            print(f"Generated shared secret: {shared_secret}")

    # Get client status
    print("\n" + "=" * 60)
    print("Client Status")
    print("=" * 60)
    status_str = get_choice(
        "Select client status:",
        ["active", "suspended", "revoked"],
        default="active"
    )
    status = ClientStatus(status_str)

    # Create client
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Client name: {client_name}")
    if api_key:
        print(f"API Key: {api_key}")
    if shared_secret:
        print(f"Shared Secret: {shared_secret}")
    print(f"Status: {status.value}")

    if not get_yes_no("\nCreate this client?", default=True):
        print("Cancelled.")
        sys.exit(0)

    # Connect to database and save
    db = get_db_connection()

    try:
        client = Client.create_new(
            client_name=client_name,
            api_key=api_key,
            shared_secret=shared_secret,
            status=status
        )

        client_id = db.save_client(client)

        print("\n" + "=" * 60)
        print("✓ Client created successfully!")
        print("=" * 60)
        print(f"Client ID: {client_id}")
        print(f"Name: {client_name}")
        if api_key:
            print(f"API Key: {api_key}")
        if shared_secret:
            print(f"Shared Secret: {shared_secret}")
        print(f"Status: {status.value}")
        print("\nIMPORTANT: Save these credentials securely. They cannot be retrieved later.")
        print("\nNext steps:")
        print("  1. Grant permissions: Use scripts/grant_permission.py")
        print("  2. View all clients: python scripts/list_clients.py")

    except Exception as e:
        print(f"\n✗ Error creating client: {e}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
