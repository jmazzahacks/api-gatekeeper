#!/usr/bin/env python
"""
Import gatekeeper state from JSON (produced by export_state.py).

Reads the JSON document from stdin and inserts non-colliding rows into the
local database, preserving the source UUIDs so foreign-key references
remain intact.

Collision policy: SKIP, never overwrite.
  - routes: skip if (domain, route_pattern) already exists on target
  - clients: skip if api_key, shared_secret, or client_id already in use
  - client_permissions: skip if either parent (client_id, route_id) was
    skipped on the target, or the (client_id, route_id) pair already exists
  - rate_limits: skip if client was skipped or a rate_limit already exists
    for that client

Console admins are NOT imported (they live in a separate table and must be
re-provisioned via the Aegis user.verified webhook).

Status messages and the import summary go to stderr.

Usage (locally):
  python scripts/import_state.py < state.json

Usage (in production via docker exec):
  ssh -l foo -p 2828 target-host \\
    'docker exec -i gatekeeper python scripts/import_state.py' < state.json
"""

import json
import sys
from typing import List

from dotenv import load_dotenv
from api_gatekeeper_models import Client, ClientPermission, RateLimit, Route
from src.utils import get_db_connection


FORMAT_VERSION = 1


def main() -> None:
    """Read export JSON from stdin and insert non-colliding rows."""
    load_dotenv()

    print("Reading export JSON from stdin...", file=sys.stderr)
    data = json.load(sys.stdin)

    fmt = data.get("format_version")
    if fmt != FORMAT_VERSION:
        print(
            f"Error: unsupported format_version {fmt!r} (expected {FORMAT_VERSION})",
            file=sys.stderr,
        )
        sys.exit(1)

    src_routes = [Route.from_dict(d) for d in data.get("routes", [])]
    src_clients = [Client.from_dict(d) for d in data.get("clients", [])]
    src_permissions = [
        ClientPermission.from_dict(d) for d in data.get("client_permissions", [])
    ]
    src_rate_limits = [RateLimit.from_dict(d) for d in data.get("rate_limits", [])]

    print(
        f"Loaded from JSON: {len(src_routes)} routes, {len(src_clients)} clients, "
        f"{len(src_permissions)} permissions, {len(src_rate_limits)} rate limits",
        file=sys.stderr,
    )

    print("Connecting to target database...", file=sys.stderr)
    db = get_db_connection(verbose=False)

    try:
        existing_routes = db.load_all_routes()
        existing_clients = db.load_all_clients()
        existing_permissions = db.load_all_permissions()
        existing_rate_limits = db.load_all_rate_limits()

        # Collision-detection sets, seeded from target state and grown on each
        # successful insert. Membership means: "this key/id is already present
        # on the target DB (either pre-existing or just inserted from source)."
        # Using one set per dimension catches both target/source collisions AND
        # duplicates within the source export.
        route_keys = {(r.domain, r.route_pattern) for r in existing_routes}
        route_ids = {r.route_id for r in existing_routes}
        api_keys = {c.api_key for c in existing_clients if c.api_key}
        shared_secrets = {c.shared_secret for c in existing_clients if c.shared_secret}
        client_ids = {c.client_id for c in existing_clients}
        perm_keys = {(p.client_id, p.route_id) for p in existing_permissions}
        perm_ids = {p.permission_id for p in existing_permissions}
        rl_client_ids = {rl.client_id for rl in existing_rate_limits}

        # --- Routes ---
        inserted_routes = 0
        skipped_routes: List[str] = []
        for route in src_routes:
            key = (route.domain, route.route_pattern)
            collisions: List[str] = []
            if key in route_keys:
                collisions.append("domain+pattern")
            if route.route_id in route_ids:
                collisions.append("route_id")
            if collisions:
                skipped_routes.append(
                    f"  - {route.domain}{route.route_pattern} "
                    f"(collision: {', '.join(collisions)})"
                )
                continue
            db.save_route(route)
            inserted_routes += 1
            route_keys.add(key)
            route_ids.add(route.route_id)

        # --- Clients ---
        inserted_clients = 0
        skipped_clients: List[str] = []
        for client in src_clients:
            collisions = []
            if client.api_key and client.api_key in api_keys:
                collisions.append("api_key")
            if client.shared_secret and client.shared_secret in shared_secrets:
                collisions.append("shared_secret")
            if client.client_id in client_ids:
                collisions.append("client_id")
            if collisions:
                skipped_clients.append(
                    f"  - {client.client_name} (collision: {', '.join(collisions)})"
                )
                continue
            db.save_client(client)
            inserted_clients += 1
            client_ids.add(client.client_id)
            if client.api_key:
                api_keys.add(client.api_key)
            if client.shared_secret:
                shared_secrets.add(client.shared_secret)

        # --- Client Permissions ---
        inserted_perms = 0
        orphan_perms = 0
        duplicate_perms = 0
        for perm in src_permissions:
            if perm.client_id not in client_ids or perm.route_id not in route_ids:
                orphan_perms += 1
                continue
            if (
                (perm.client_id, perm.route_id) in perm_keys
                or perm.permission_id in perm_ids
            ):
                duplicate_perms += 1
                continue
            db.save_permission(perm)
            inserted_perms += 1
            perm_keys.add((perm.client_id, perm.route_id))
            perm_ids.add(perm.permission_id)

        # --- Rate Limits ---
        inserted_rls = 0
        orphan_rls = 0
        duplicate_rls = 0
        for rl in src_rate_limits:
            if rl.client_id not in client_ids:
                orphan_rls += 1
                continue
            if rl.client_id in rl_client_ids:
                duplicate_rls += 1
                continue
            db.save_rate_limit(rl)
            inserted_rls += 1
            rl_client_ids.add(rl.client_id)

        # --- Summary ---
        print("\n" + "=" * 70, file=sys.stderr)
        print("Import summary:", file=sys.stderr)
        print(
            f"  routes:             inserted {inserted_routes}, "
            f"skipped {len(skipped_routes)}",
            file=sys.stderr,
        )
        for line in skipped_routes:
            print(line, file=sys.stderr)
        print(
            f"  clients:            inserted {inserted_clients}, "
            f"skipped {len(skipped_clients)}",
            file=sys.stderr,
        )
        for line in skipped_clients:
            print(line, file=sys.stderr)
        print(
            f"  client_permissions: inserted {inserted_perms}, "
            f"orphaned {orphan_perms}, duplicate {duplicate_perms}",
            file=sys.stderr,
        )
        print(
            f"  rate_limits:        inserted {inserted_rls}, "
            f"orphaned {orphan_rls}, duplicate {duplicate_rls}",
            file=sys.stderr,
        )
        print("=" * 70, file=sys.stderr)
    finally:
        db.close()


if __name__ == "__main__":
    main()
