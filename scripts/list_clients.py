#!/usr/bin/env python
"""
Script to list all clients in the API auth service.

Usage:
  python scripts/list_clients.py
"""

from dotenv import load_dotenv
from src.utils import get_db_connection


def format_credential(value: str, show_full: bool = False) -> str:
    """Format a credential for display (truncated or full)."""
    if not value:
        return "None"
    if show_full:
        return value
    # Show first 8 chars + ... for security
    return f"{value[:8]}..." if len(value) > 8 else value


def main():
    """Main function to list all clients."""
    load_dotenv()

    print("=" * 100)
    print("API Clients")
    print("=" * 100)

    db = get_db_connection(verbose=False)

    try:
        clients = db.load_all_clients()

        if not clients:
            print("\nNo clients found.")
            print("\nTo create a client:")
            print("  python scripts/create_client.py")
            return

        print(f"\nTotal clients: {len(clients)}\n")

        # Print header
        print(f"{'Client ID':<38} {'Name':<25} {'API Key':<15} {'Secret':<15} {'Status':<10}")
        print("-" * 100)

        # Print each client
        for client in clients:
            client_id_short = str(client.client_id)
            name_truncated = (client.client_name[:22] + "...") if len(client.client_name) > 25 else client.client_name
            api_key_display = format_credential(client.api_key)
            secret_display = format_credential(client.shared_secret)
            status_display = client.status.value

            print(f"{client_id_short:<38} {name_truncated:<25} {api_key_display:<15} {secret_display:<15} {status_display:<10}")

        print("\n" + "=" * 100)
        print("Legend:")
        print("  API Key: Shows first 8 characters (truncated for security)")
        print("  Secret: Shows first 8 characters (truncated for security)")
        print("\nTo view full credentials for a client:")
        print("  python scripts/show_client.py <client_id>")
        print("\nTo delete a client:")
        print("  python scripts/delete_client.py <client_id>")

    except Exception as e:
        print(f"\n✗ Error loading clients: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
