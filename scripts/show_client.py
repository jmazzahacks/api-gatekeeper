#!/usr/bin/env python
"""
Script to show full details for a specific client in the API auth service.

Usage:
  python scripts/show_client.py <client_id>
  python scripts/show_client.py  # Interactive mode
"""

import sys
from datetime import datetime
from dotenv import load_dotenv

from src.utils import get_db_connection


def format_timestamp(unix_ts: int) -> str:
    """Format a Unix timestamp for display."""
    dt = datetime.fromtimestamp(unix_ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def show_client_details(client_id: str) -> bool:
    """Show full details for a client by its ID."""
    db = get_db_connection(verbose=False)

    try:
        client = db.load_client_by_id(client_id)

        if not client:
            print(f"Client not found: {client_id}")
            return False

        print("=" * 80)
        print("Client Details")
        print("=" * 80)
        print(f"Client ID:     {client.client_id}")
        print(f"Name:          {client.client_name}")
        print(f"Status:        {client.status.value}")
        if client.legacy_key_id:
            print(f"Legacy Key ID: {client.legacy_key_id}")
        print(f"Created:       {format_timestamp(client.created_at)}")
        print(f"Updated:       {format_timestamp(client.updated_at)}")

        print("\n" + "-" * 80)
        print("Credentials")
        print("-" * 80)
        if client.api_key:
            print(f"API Key:       {client.api_key}")
        else:
            print("API Key:       (none)")

        if client.shared_secret:
            print(f"Shared Secret: {client.shared_secret}")
        else:
            print("Shared Secret: (none)")

        # Load and display permissions
        permissions = db.load_permissions_by_client(client_id)
        print("\n" + "-" * 80)
        print(f"Permissions ({len(permissions)})")
        print("-" * 80)

        if permissions:
            for perm in permissions:
                route = db.load_route_by_id(perm.route_id)
                methods_str = ", ".join([m.value for m in perm.allowed_methods])
                if route:
                    print(f"  {route.route_pattern:<40} ({route.domain}) [{methods_str}]")
                else:
                    print(f"  {perm.route_id:<40} [{methods_str}] (route not found)")
        else:
            print("  (no permissions granted)")

        # Load and display rate limit
        rate_limit = db.load_rate_limit_by_client(client_id)
        print("\n" + "-" * 80)
        print("Rate Limit")
        print("-" * 80)

        if rate_limit:
            print(f"  Requests:    {rate_limit.requests_per_window}")
            print(f"  Window:      {rate_limit.window_seconds} seconds")
        else:
            print("  (no rate limit configured)")

        print("\n" + "=" * 80)
        return True

    except Exception as e:
        print(f"Error loading client: {e}")
        return False
    finally:
        db.close()


def interactive_select() -> None:
    """Interactive mode to select and show a client."""
    db = get_db_connection(verbose=False)

    try:
        clients = db.load_all_clients()

        if not clients:
            print("No clients found.")
            return

        print("\n" + "=" * 80)
        print("Select a client to view")
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
                    show_client_details(selected_client.client_id)
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
        show_client_details(client_id)
    else:
        interactive_select()


if __name__ == "__main__":
    main()
