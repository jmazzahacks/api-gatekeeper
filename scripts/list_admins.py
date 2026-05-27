#!/usr/bin/env python
"""
Script to list all console admins in the gatekeeper.

Console admins are the human users (linked to Aegis accounts) authorized to
administer the gatekeeper via the management console. They are matched on
`aegis_user_id` — if the value stored here doesn't equal the user's id on the
Aegis instance the backend introspects against, every /api/admin/* call 401s.

Usage:
  python scripts/list_admins.py
"""

from dotenv import load_dotenv
from src.utils import get_db_connection


def main():
    """Main function to list all console admins."""
    load_dotenv()

    print("=" * 90)
    print("Console Admins")
    print("=" * 90)

    db = get_db_connection(verbose=False)

    try:
        admins = db.load_all_admins()

        if not admins:
            print("\nNo console admins found.")
            print("\nAdmins are provisioned via the Aegis `user.verified` webhook.")
            return

        print(f"\nTotal admins: {len(admins)}\n")

        print(f"{'Aegis User ID':<14} {'Email':<40} {'Admin ID':<38}")
        print("-" * 90)

        for admin in admins:
            print(f"{admin.aegis_user_id:<14} {admin.email:<40} {str(admin.admin_id):<38}")

        print("\n" + "=" * 90)
        print("The `aegis_user_id` column must match the user's id on the Aegis")
        print("instance the backend introspects against, or admin auth returns 401.")

    except Exception as e:
        print(f"\n✗ Error loading admins: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
