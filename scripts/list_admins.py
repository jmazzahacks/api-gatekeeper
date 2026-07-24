#!/usr/bin/env python
"""
Script to list all console admins in the gatekeeper.

Console admins are the human users (linked to Aegis accounts) authorized to
administer the gatekeeper via the management console. After Aegis phase-3
(UUID-only contract), `aegis_uuid` is the source of truth for admin identity.

Usage:
  python scripts/list_admins.py
"""

from dotenv import load_dotenv
from src.utils import get_db_connection


def main():
    """Main function to list all console admins."""
    load_dotenv()

    print("=" * 128)
    print("Console Admins")
    print("=" * 128)

    db = get_db_connection(verbose=False)

    try:
        admins = db.load_all_admins()

        if not admins:
            print("\nNo console admins found.")
            print("\nAdmins are provisioned via the Aegis `user.verified` webhook.")
            return

        print(f"\nTotal admins: {len(admins)}\n")

        print(
            f"{'Aegis UUID':<38} "
            f"{'Email':<40} "
            f"{'Admin ID':<38}"
        )
        print("-" * 128)

        for admin in admins:
            print(
                f"{admin.aegis_uuid:<38} "
                f"{admin.email:<40} "
                f"{str(admin.admin_id):<38}"
            )

        print("\n" + "=" * 128)
        print("Auth resolves the Aegis /me UUID against aegis_uuid.")

    except Exception as e:
        print(f"\n[ERROR] loading admins: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
