#!/usr/bin/env python
"""
Export gatekeeper state to JSON for migration to another instance.

Writes a JSON document to stdout containing all routes, clients, client
permissions, and rate limits. Console admins are intentionally excluded —
they must be re-provisioned via the Aegis user.verified webhook.

Status messages go to stderr so stdout stays a clean JSON stream.

Usage (locally):
  python scripts/export_state.py > state.json

Usage (in production via docker exec):
  ssh -l foo -p 2828 source-host \\
    'docker exec gatekeeper python scripts/export_state.py' > state.json
"""

import json
import sys

from dotenv import load_dotenv
from src.utils import get_db_connection


FORMAT_VERSION = 1


def main() -> None:
    """Load all gatekeeper state and emit it as JSON on stdout."""
    load_dotenv()

    print("Connecting to database...", file=sys.stderr)
    db = get_db_connection(verbose=False)

    try:
        print("Loading routes...", file=sys.stderr)
        routes = db.load_all_routes()

        print("Loading clients...", file=sys.stderr)
        clients = db.load_all_clients()

        print("Loading client permissions...", file=sys.stderr)
        permissions = db.load_all_permissions()

        print("Loading rate limits...", file=sys.stderr)
        rate_limits = db.load_all_rate_limits()

        export = {
            "format_version": FORMAT_VERSION,
            "routes": [r.to_dict() for r in routes],
            "clients": [c.to_dict() for c in clients],
            "client_permissions": [p.to_dict() for p in permissions],
            "rate_limits": [rl.to_dict() for rl in rate_limits],
        }

        json.dump(export, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")

        print(
            f"Exported: {len(routes)} routes, {len(clients)} clients, "
            f"{len(permissions)} permissions, {len(rate_limits)} rate limits",
            file=sys.stderr,
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
