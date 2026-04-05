#!/usr/bin/env python
"""
Interactive script to update an existing client in the API auth service.

Usage:
  python scripts/update_client.py <client_id>
  python scripts/update_client.py  # Interactive mode
"""

import sys
import time
from datetime import datetime
from dotenv import load_dotenv

from src.utils import get_db_connection
from api_gatekeeper_models import Client


def format_timestamp(unix_ts: int) -> str:
    """Format a Unix timestamp for display."""
    dt = datetime.fromtimestamp(unix_ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


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


def update_client_interactive(client_id: str) -> bool:
    """Interactively update a client."""
    db = get_db_connection(verbose=False)

    try:
        client = db.load_client_by_id(client_id)

        if not client:
            print(f"Client not found: {client_id}")
            return False

        print("=" * 80)
        print("Update Client")
        print("=" * 80)
        print("\nCurrent client details:")
        print("-" * 80)
        print(f"Client ID:     {client.client_id}")
        print(f"Name:          {client.client_name}")
        print(f"Status:        {client.status.value}")
        print(f"Created:       {format_timestamp(client.created_at)}")
        print(f"Updated:       {format_timestamp(client.updated_at)}")
        print("-" * 80)

        print("\nPress Enter to keep current value, or enter a new value.")
        print()

        new_name = get_input("Client name", client.client_name)

        # Show summary of changes
        print("\n" + "=" * 80)
        print("Summary of Changes")
        print("=" * 80)

        changes = []
        if new_name != client.client_name:
            changes.append(f"Name:  {client.client_name} -> {new_name}")

        if not changes:
            print("\nNo changes detected.")
            return True

        for change in changes:
            print(f"  {change}")

        print()
        response = input("Apply these changes? Type 'update' to confirm: ").strip().lower()
        if response != "update":
            print("Cancelled.")
            return False

        updated_client = Client(
            client_id=client.client_id,
            client_name=new_name,
            shared_secret=client.shared_secret,
            api_key=client.api_key,
            status=client.status,
            created_at=client.created_at,
            updated_at=int(time.time())
        )

        db.save_client(updated_client)
        print(f"\nClient updated successfully: {client_id}")
        return True

    except Exception as e:
        print(f"Error updating client: {e}")
        return False
    finally:
        db.close()


def interactive_select() -> None:
    """Interactive mode to select and update a client."""
    db = get_db_connection(verbose=False)

    try:
        clients = db.load_all_clients()

        if not clients:
            print("No clients found.")
            return

        print("\n" + "=" * 80)
        print("Select a client to update")
        print("=" * 80)

        for i, client in enumerate(clients, 1):
            api_key_display = f"{client.api_key[:8]}..." if client.api_key else "None"
            print(f"{i:2}. {client.client_name:<30} (API: {api_key_display}, {client.status.value})")

        print(" 0. Cancel")

        while True:
            try:
                choice = input(f"\nEnter choice (0-{len(clients)}): ").strip()
                idx = int(choice)

                if idx == 0:
                    print("Cancelled.")
                    return

                if 1 <= idx <= len(clients):
                    selected_client = clients[idx - 1]
                    db.close()
                    print()
                    update_client_interactive(selected_client.client_id)
                    return

                print(f"Invalid choice. Please enter a number between 0 and {len(clients)}")
            except ValueError:
                print("Invalid input. Please enter a number.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()


def main() -> None:
    """Main function."""
    load_dotenv()

    if len(sys.argv) > 1:
        client_id = sys.argv[1]
        update_client_interactive(client_id)
    else:
        interactive_select()


if __name__ == "__main__":
    main()
