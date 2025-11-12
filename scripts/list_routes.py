#!/usr/bin/env python
"""
Script to list all routes in the API auth service.

Usage:
  python scripts/list_routes.py
"""

from dotenv import load_dotenv

from src.utils import get_db_connection


def main():
    """Main function to list all routes."""
    load_dotenv()

    print("=" * 80)
    print("All Routes")
    print("=" * 80)
    print()

    # Connect to database
    db = get_db_connection()

    # Load all routes
    routes = db.load_all_routes()

    if not routes:
        print("No routes found in the database.")
        db.close()
        return

    print(f"Found {len(routes)} route(s):\n")

    for i, route in enumerate(routes, 1):
        print(f"{i}. Route ID: {route.route_id}")
        print(f"   Pattern:  {route.route_pattern}")
        print(f"   Domain:   {route.domain}")
        print(f"   Service:  {route.service_name}")
        print(f"   Methods:")

        for method, auth in route.methods.items():
            if auth.auth_required:
                auth_desc = f"{auth.auth_type.value} authentication required"
            else:
                auth_desc = "public (no auth)"
            print(f"     {method.value:8} → {auth_desc}")

        print()

    db.close()


if __name__ == "__main__":
    main()
