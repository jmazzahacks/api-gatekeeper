#!/usr/bin/env python
"""
Backfill `console_admins.aegis_uuid` from Aegis, mapping each legacy integer
`aegis_user_id` to its UUID via the tenant-key-gated Aegis API.

Aegis is migrating identifiers from auto-increment integers to UUIDs. Phase 1
of that migration is a shim: every endpoint accepts BOTH forms and every
response carries both `id` and `uuid`. This script uses that window to fill
the new `aegis_uuid` column on our end so we can survive Aegis phase 2
(contract), which drops the integer column entirely.

Prerequisites:
  - `src/database/schema.sql` has been applied (adds the `aegis_uuid` column).
  - `AEGIS_API_URL`, `AEGIS_SITE_ID`, `AEGIS_TENANT_API_KEY` are set in the
    environment (same variables the running backend uses).

Usage:
  python scripts/backfill_aegis_uuid.py            # writes to DB
  python scripts/backfill_aegis_uuid.py --dry-run  # reports what would change

Idempotent: rows already carrying an `aegis_uuid` are left alone.
"""
import argparse
import sys
from typing import List

import psycopg2
from dotenv import load_dotenv

from api_gatekeeper_models import ConsoleAdmin
from byteforge_aegis_client import AegisClient
from src.auth import aegis_tenant_client
from src.database.driver import AuthServiceDB
from src.utils import get_db_connection


def _guard_column_exists(db: AuthServiceDB) -> bool:
    """
    Return True iff `console_admins.aegis_uuid` exists. Guards the dry-run
    path so we don't throw before the operator has applied schema.sql.
    """
    from psycopg2.extras import RealDictCursor
    with db.get_cursor(commit=False, cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT 1 AS found FROM information_schema.columns
            WHERE table_name = 'console_admins' AND column_name = 'aegis_uuid'
            """
        )
        return cur.fetchone() is not None


def _backfill_one(
    db: AuthServiceDB,
    client: AegisClient,
    admin: ConsoleAdmin,
    dry_run: bool,
) -> str:
    """
    Look up a single admin's Aegis UUID and (unless dry_run) write it.

    Returns one of: 'ok', 'skip-no-uuid', 'skip-already', 'fail-lookup',
    'fail-collision'. Caller aggregates counts and prints per-row lines.
    """
    try:
        user = client.get_user(admin.aegis_user_id)
    except Exception as exc:
        print(
            f"  [ERROR] aegis_user_id={admin.aegis_user_id} email={admin.email}: "
            f"lookup failed ({exc})"
        )
        return 'fail-lookup'

    if not user.uuid:
        print(
            f"  [ERROR] aegis_user_id={admin.aegis_user_id} email={admin.email}: "
            "Aegis response has no uuid — is Aegis still pre-shim?"
        )
        return 'skip-no-uuid'

    if dry_run:
        print(
            f"  [DRY-RUN] aegis_user_id={admin.aegis_user_id} "
            f"email={admin.email} -> uuid={user.uuid}"
        )
        return 'ok'

    try:
        wrote = db.backfill_admin_aegis_uuid(admin.aegis_user_id, user.uuid)
    except psycopg2.errors.UniqueViolation:
        print(
            f"  [ERROR] aegis_user_id={admin.aegis_user_id} email={admin.email}: "
            f"uuid={user.uuid} is already held by a different admin row — "
            "resolve the anomaly manually before re-running."
        )
        return 'fail-collision'

    if wrote:
        print(
            f"  [OK] aegis_user_id={admin.aegis_user_id} "
            f"email={admin.email} -> uuid={user.uuid}"
        )
        return 'ok'
    print(
        f"  [SKIP] aegis_user_id={admin.aegis_user_id} email={admin.email}: "
        "row already has aegis_uuid (concurrent webhook backfill?)"
    )
    return 'skip-already'


def _backfill_all(
    db: AuthServiceDB,
    client: AegisClient,
    needs_backfill: List[ConsoleAdmin],
    dry_run: bool,
) -> int:
    """Run backfill for every admin in `needs_backfill`; return the failure count."""
    failures = 0
    for admin in needs_backfill:
        result = _backfill_one(db, client, admin, dry_run)
        if result.startswith('fail'):
            failures += 1
    return failures


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Look up UUIDs but do not write them; report the plan and exit.',
    )
    args = parser.parse_args()

    # aegis_tenant_client() raises RuntimeError if any of AEGIS_API_URL /
    # AEGIS_SITE_ID / AEGIS_TENANT_API_KEY is missing — same contract the
    # running backend uses, so config drift is impossible.
    try:
        client = aegis_tenant_client()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    db = get_db_connection(verbose=False)
    try:
        if not _guard_column_exists(db):
            print(
                "[ERROR] console_admins.aegis_uuid does not exist yet. "
                "Apply src/database/schema.sql before running this script.",
                file=sys.stderr,
            )
            return 2

        admins = db.load_all_admins()
        needs_backfill = [a for a in admins if a.aegis_uuid is None]
        print(f"Total console admins: {len(admins)}")
        print(f"  Already backfilled: {len(admins) - len(needs_backfill)}")
        print(f"  Needs backfill:     {len(needs_backfill)}")
        if not needs_backfill:
            print("Nothing to do.")
            return 0

        failures = _backfill_all(db, client, needs_backfill, args.dry_run)

        print()
        if args.dry_run:
            print(f"Dry run: would have written {len(needs_backfill) - failures} row(s).")
        else:
            print(f"Attempted {len(needs_backfill)} row(s); {failures} failure(s).")

        return 1 if failures else 0
    finally:
        db.close()


if __name__ == '__main__':
    sys.exit(main())
