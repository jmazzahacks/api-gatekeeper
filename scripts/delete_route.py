#!/usr/bin/env python
"""
Script to delete a route by UUID in the API auth service.

Usage:
  python scripts/delete_route.py <route_id>
"""

import sys
from dotenv import load_dotenv

from src.utils import get_db_connection


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no input from user."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{prompt} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ['y', 'yes']


def main():
    """Main function to delete a route by UUID."""
    load_dotenv()

    if len(sys.argv) != 2:
        print("Usage: python scripts/delete_route.py <route_id>")
        print("\nExample:")
        print("  python scripts/delete_route.py 86264801-5249-4839-bd45-c26679d12765")
        sys.exit(1)

    route_id = sys.argv[1]

    print("=" * 80)
    print("Delete Route")
    print("=" * 80)
    print()

    # Connect to database
    db = get_db_connection()

    # Load the route to display what will be deleted
    route = db.load_route_by_id(route_id)

    if not route:
        print(f"✗ Error: Route with ID '{route_id}' not found.")
        db.close()
        sys.exit(1)

    # Display route details
    print(f"Route ID:  {route.route_id}")
    print(f"Pattern:   {route.route_pattern}")
    print(f"Service:   {route.service_name}")
    print(f"Methods:")

    for method, auth in route.methods.items():
        if auth.auth_required:
            auth_desc = f"{auth.auth_type.value} authentication required"
        else:
            auth_desc = "public (no auth)"
        print(f"  {method.value:8} → {auth_desc}")

    print("\n" + "=" * 80)

    # Confirm deletion
    if not get_yes_no("Are you sure you want to delete this route?", default=False):
        print("Deletion cancelled.")
        db.close()
        sys.exit(0)

    # Delete the route
    success = db.delete_route(route_id)

    if success:
        print(f"\n✓ Route '{route_id}' deleted successfully.")
    else:
        print(f"\n✗ Error: Failed to delete route '{route_id}'.")
        db.close()
        sys.exit(1)

    db.close()


if __name__ == "__main__":
    main()
