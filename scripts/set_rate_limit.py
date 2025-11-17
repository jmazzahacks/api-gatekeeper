#!/usr/bin/env python
"""
Script to set or update rate limits for clients.

Usage:
  python scripts/set_rate_limit.py
"""

from dotenv import load_dotenv
from src.utils import get_db_connection
from src.models.rate_limit import RateLimit


def main():
    """Main function to set rate limit for a client."""
    load_dotenv()

    print("=" * 80)
    print("Set Rate Limit for Client")
    print("=" * 80)

    db = get_db_connection(verbose=False)

    try:
        clients = db.load_all_clients()
        if not clients:
            print("\nNo clients found. Create a client first:")
            print("  python scripts/create_client.py")
            return

        print(f"\nAvailable clients ({len(clients)}):\n")
        for client in clients:
            current_limit = db.load_rate_limit_by_client(client.client_id)
            limit_display = str(current_limit.requests_per_day) if current_limit else "unlimited"
            print(f"  {client.client_id} - {client.client_name} ({limit_display} req/24h)")

        print()
        client_id = input("Enter client ID: ").strip()

        client = db.load_client_by_id(client_id)
        if not client:
            print(f"\n✗ Client not found: {client_id}")
            return

        current_limit = db.load_rate_limit_by_client(client_id)
        if current_limit:
            print(f"\nCurrent rate limit: {current_limit.requests_per_day} requests per 24 hours")
        else:
            print("\nNo rate limit currently set (unlimited)")

        limit_input = input("\nEnter requests per 24 hours (or 'remove' to remove limit): ").strip()

        if limit_input.lower() == 'remove':
            if current_limit:
                db.delete_rate_limit(client_id)
                print(f"\n✓ Rate limit removed for {client.client_name}")
            else:
                print("\nNo rate limit to remove")
            return

        try:
            requests_per_day = int(limit_input)
            if requests_per_day <= 0:
                print("\n✗ Rate limit must be a positive integer")
                return
        except ValueError:
            print("\n✗ Invalid input. Enter a positive integer or 'remove'")
            return

        rate_limit = RateLimit.create_new(client_id, requests_per_day)
        db.save_rate_limit(rate_limit)

        print(f"\n✓ Rate limit set for {client.client_name}")
        print(f"  Requests per 24 hours: {requests_per_day}")

    except Exception as e:
        print(f"\n✗ Error setting rate limit: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
