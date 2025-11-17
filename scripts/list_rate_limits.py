#!/usr/bin/env python
"""
Script to list all rate limit configurations.

Usage:
  python scripts/list_rate_limits.py
"""

from dotenv import load_dotenv
from src.utils import get_db_connection


def main():
    """Main function to list all rate limits."""
    load_dotenv()

    print("=" * 100)
    print("Client Rate Limits")
    print("=" * 100)

    db = get_db_connection(verbose=False)

    try:
        clients = db.load_all_clients()

        if not clients:
            print("\nNo clients found.")
            return

        print(f"\n{'Client ID':<38} {'Client Name':<25} {'Limit (req/24h)':<20}")
        print("-" * 100)

        limited_count = 0
        unlimited_count = 0

        for client in clients:
            rate_limit = db.load_rate_limit_by_client(client.client_id)
            name_truncated = (client.client_name[:22] + "...") if len(client.client_name) > 25 else client.client_name

            if rate_limit:
                limit_display = str(rate_limit.requests_per_day)
                limited_count += 1
            else:
                limit_display = "unlimited"
                unlimited_count += 1

            print(f"{client.client_id:<38} {name_truncated:<25} {limit_display:<20}")

        print("\n" + "=" * 100)
        print(f"Summary: {limited_count} with limits, {unlimited_count} unlimited")
        print("\nTo set a rate limit:")
        print("  python scripts/set_rate_limit.py")

    except Exception as e:
        print(f"\n✗ Error loading rate limits: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
