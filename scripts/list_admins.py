#!/usr/bin/env python
"""
Script to list all console admins in the gatekeeper.

Console admins are the human users (linked to Aegis accounts) authorized to
administer the gatekeeper via the management console. After Aegis phase-3
(UUID-only contract), `aegis_uuid` is the source of truth for admin identity.
`aegis_user_id` remains as read-only historical data on shim-era rows.

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
            f"{'Legacy Aegis ID':<16} "
            f"{'Email':<40} "
            f"{'Admin ID':<38}"
        )
        print("-" * 128)

        for admin in admins:
            legacy_id = str(admin.aegis_user_id) if admin.aegis_user_id is not None else '-'
            print(
                f"{admin.aegis_uuid:<38} "
                f"{legacy_id:<16} "
                f"{admin.email:<40} "
                f"{str(admin.admin_id):<38}"
            )

        print("\n" + "=" * 128)
        print("Auth resolves the Aegis /me UUID against aegis_uuid. The legacy")
        print("integer id column is read-only historical data and no longer")
        print("populated on new admins.")

    except Exception as e:
        print(f"\n[ERROR] loading admins: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
