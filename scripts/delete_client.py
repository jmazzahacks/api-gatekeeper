#!/usr/bin/env python
"""
Script to delete a client from the API auth service.

Usage:
  python scripts/delete_client.py <client_id>
  python scripts/delete_client.py  # Interactive mode
"""

import sys
from dotenv import load_dotenv

from src.utils import get_db_connection


def confirm_deletion(client) -> bool:
    """Ask user to confirm deletion."""
    print("\n" + "=" * 80)
    print("WARNING: You are about to delete this client")
    print("=" * 80)
    print(f"Client ID: {client.client_id}")
    print(f"Name: {client.client_name}")
    if client.api_key:
        print(f"API Key: {client.api_key[:8]}...")
    if client.shared_secret:
        print(f"Shared Secret: {client.shared_secret[:8]}...")
    print(f"Status: {client.status.value}")

    # Check if client has permissions
    db = get_db_connection(verbose=False)
    try:
        permissions = db.load_permissions_by_client(client.client_id)
        if permissions:
            print(f"\n⚠ This client has {len(permissions)} permission(s) that will also be deleted.")
            print("Associated routes:")
            for perm in permissions:
                route = db.load_route_by_id(perm.route_id)
                if route:
                    methods_str = ", ".join([m.value for m in perm.allowed_methods])
                    print(f"  - {route.route_pattern} ({methods_str})")
    finally:
        db.close()

    print("\n" + "=" * 80)
    response = input("Type 'delete' to confirm deletion: ").strip()
    return response == 'delete'


def delete_client_by_id(client_id: str) -> bool:
    """Delete a client by its ID."""
    db = get_db_connection(verbose=False)

    try:
        # Load client to show info
        client = db.load_client_by_id(client_id)

        if not client:
            print(f"✗ Client not found: {client_id}")
            return False

        # Confirm deletion
        if not confirm_deletion(client):
            print("Deletion cancelled.")
            return False

        # Delete the client
        success = db.delete_client(client_id)

        if success:
            print(f"\n✓ Client deleted successfully: {client.client_name} ({client_id})")
            return True
        else:
            print(f"\n✗ Failed to delete client: {client_id}")
            return False

    except Exception as e:
        print(f"\n✗ Error deleting client: {e}")
        return False
    finally:
        db.close()


def interactive_delete():
    """Interactive mode to select and delete a client."""
    db = get_db_connection(verbose=False)

    try:
        clients = db.load_all_clients()

        if not clients:
            print("No clients found.")
            return

        print("\n" + "=" * 80)
        print("Select a client to delete")
        print("=" * 80)

        for i, client in enumerate(clients, 1):
            api_key_display = f"{client.api_key[:8]}..." if client.api_key else "None"
            secret_display = f"{client.shared_secret[:8]}..." if client.shared_secret else "None"
            print(f"{i:2}. {client.client_name:<30} (API: {api_key_display}, Secret: {secret_display}, {client.status.value})")

        print(f" 0. Cancel")

        while True:
            try:
                choice = input(f"\nEnter choice (0-{len(clients)}): ").strip()
                idx = int(choice)

                if idx == 0:
                    print("Cancelled.")
                    return

                if 1 <= idx <= len(clients):
                    selected_client = clients[idx - 1]
                    delete_client_by_id(selected_client.client_id)
                    return

                print(f"Invalid choice. Please enter a number between 0 and {len(clients)}")
            except ValueError:
                print("Invalid input. Please enter a number.")

    except Exception as e:
        print(f"\n✗ Error: {e}")
    finally:
        db.close()


def main():
    """Main function."""
    load_dotenv()

    if len(sys.argv) > 1:
        # Client ID provided as argument
        client_id = sys.argv[1]
        delete_client_by_id(client_id)
    else:
        # Interactive mode
        interactive_delete()


if __name__ == "__main__":
    main()
