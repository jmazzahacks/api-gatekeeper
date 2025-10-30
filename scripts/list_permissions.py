#!/usr/bin/env python
"""
Script to list permissions in the API auth service.

Usage:
  python scripts/list_permissions.py                    # List all permissions
  python scripts/list_permissions.py --client <id>      # List permissions for a client
  python scripts/list_permissions.py --route <id>       # List permissions for a route
"""

import sys
from dotenv import load_dotenv

from src.utils import get_db_connection


def list_all_permissions(db):
    """List all permissions grouped by client."""
    clients = db.load_all_clients()

    if not clients:
        print("No clients found.")
        return

    print("\n" + "=" * 100)
    print("All Client Permissions")
    print("=" * 100)

    total_permissions = 0

    for client in clients:
        permissions = db.load_permissions_by_client(client.client_id)

        if not permissions:
            continue

        total_permissions += len(permissions)

        # Client header
        status_indicator = "✓" if client.is_active() else "✗"
        print(f"\n{status_indicator} {client.client_name} ({client.client_id})")
        print("  " + "-" * 96)

        # List permissions
        for perm in permissions:
            route = db.load_route_by_id(perm.route_id)
            if route:
                methods_str = ", ".join([m.value for m in perm.allowed_methods])
                print(f"  → {route.route_pattern:<35} [{route.service_name:<20}] {methods_str}")

    if total_permissions == 0:
        print("\nNo permissions found.")
        print("\nTo grant permissions:")
        print("  python scripts/grant_permission.py")
    else:
        print(f"\n{'=' * 100}")
        print(f"Total: {total_permissions} permission(s) across {len([c for c in clients if db.load_permissions_by_client(c.client_id)])} client(s)")


def list_permissions_by_client(db, client_id: str):
    """List all permissions for a specific client."""
    client = db.load_client_by_id(client_id)

    if not client:
        print(f"✗ Client not found: {client_id}")
        return

    permissions = db.load_permissions_by_client(client_id)

    print("\n" + "=" * 100)
    print(f"Permissions for Client: {client.client_name}")
    print("=" * 100)
    print(f"Client ID: {client.client_id}")
    print(f"Status: {client.status.value}")

    if client.api_key:
        print(f"API Key: {client.api_key[:8]}...")
    if client.shared_secret:
        print(f"Shared Secret: {client.shared_secret[:8]}...")

    if not permissions:
        print("\n⚠ This client has no permissions.")
        print("\nTo grant permissions:")
        print(f"  python scripts/grant_permission.py {client_id} <route_id>")
        return

    print(f"\nGranted Routes ({len(permissions)}):")
    print("-" * 100)
    print(f"{'Route Pattern':<35} {'Service':<25} {'Allowed Methods':<30} {'Permission ID'}")
    print("-" * 100)

    for perm in permissions:
        route = db.load_route_by_id(perm.route_id)
        if route:
            methods_str = ", ".join([m.value for m in perm.allowed_methods])
            print(f"{route.route_pattern:<35} {route.service_name:<25} {methods_str:<30} {perm.permission_id}")

    print("=" * 100)


def list_permissions_by_route(db, route_id: str):
    """List all permissions for a specific route."""
    route = db.load_route_by_id(route_id)

    if not route:
        print(f"✗ Route not found: {route_id}")
        return

    permissions = db.load_permissions_by_route(route_id)

    print("\n" + "=" * 100)
    print(f"Permissions for Route: {route.route_pattern}")
    print("=" * 100)
    print(f"Route ID: {route.route_id}")
    print(f"Service: {route.service_name}")

    # Show route's auth requirements
    print(f"\nRoute authentication requirements:")
    for method, method_auth in route.methods.items():
        if method_auth.auth_required:
            print(f"  {method.value:<8} - Requires {method_auth.auth_type.value}")
        else:
            print(f"  {method.value:<8} - Public (no auth)")

    if not permissions:
        print("\n⚠ No clients have permission to access this route.")
        print("\nTo grant permissions:")
        print(f"  python scripts/grant_permission.py <client_id> {route_id}")
        return

    print(f"\nAuthorized Clients ({len(permissions)}):")
    print("-" * 100)
    print(f"{'Client Name':<30} {'Allowed Methods':<25} {'Status':<10} {'Permission ID'}")
    print("-" * 100)

    for perm in permissions:
        client = db.load_client_by_id(perm.client_id)
        if client:
            methods_str = ", ".join([m.value for m in perm.allowed_methods])
            status_indicator = "✓" if client.is_active() else "✗"
            print(f"{client.client_name:<30} {methods_str:<25} {status_indicator} {client.status.value:<9} {perm.permission_id}")

    print("=" * 100)


def main():
    """Main function."""
    load_dotenv()

    db = get_db_connection(verbose=False)

    try:
        if len(sys.argv) == 1:
            # No arguments - list all permissions
            list_all_permissions(db)

        elif len(sys.argv) == 3:
            flag = sys.argv[1]
            entity_id = sys.argv[2]

            if flag == "--client":
                list_permissions_by_client(db, entity_id)
            elif flag == "--route":
                list_permissions_by_route(db, entity_id)
            else:
                print(f"Unknown flag: {flag}")
                print("\nUsage:")
                print("  python scripts/list_permissions.py                    # List all")
                print("  python scripts/list_permissions.py --client <id>      # By client")
                print("  python scripts/list_permissions.py --route <id>       # By route")
                sys.exit(1)
        else:
            print("Usage:")
            print("  python scripts/list_permissions.py                    # List all")
            print("  python scripts/list_permissions.py --client <id>      # By client")
            print("  python scripts/list_permissions.py --route <id>       # By route")
            sys.exit(1)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


if __name__ == "__main__":
    main()
