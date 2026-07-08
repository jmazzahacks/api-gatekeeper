#!/usr/bin/env python
"""
Script to list all console admins in the gatekeeper.

Console admins are the human users (linked to Aegis accounts) authorized to
administer the gatekeeper via the management console. Auth is UUID-first
with an INT fallback during the Aegis phase-1 shim — `aegis_uuid` (once
backfilled) is the source of truth; `aegis_user_id` remains as the legacy
integer id until Aegis phase-2 lands.

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

        backfilled = sum(1 for a in admins if a.aegis_uuid is not None)
        print(f"\nTotal admins: {len(admins)}  (aegis_uuid backfilled: {backfilled}/{len(admins)})\n")

        print(
            f"{'Aegis User ID':<14} "
            f"{'Aegis UUID':<38} "
            f"{'Email':<40} "
            f"{'Admin ID':<38}"
        )
        print("-" * 128)

        for admin in admins:
            uuid_display = admin.aegis_uuid or '(unbackfilled)'
            print(
                f"{admin.aegis_user_id:<14} "
                f"{uuid_display:<38} "
                f"{admin.email:<40} "
                f"{str(admin.admin_id):<38}"
            )

        print("\n" + "=" * 128)
        print("Auth is UUID-first with an INT fallback (fail-closed when the row")
        print("has been backfilled with a different aegis_uuid). Run")
        print("scripts/backfill_aegis_uuid.py to populate aegis_uuid on any row")
        print("marked (unbackfilled).")

    except Exception as e:
        print(f"\n✗ Error loading admins: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
