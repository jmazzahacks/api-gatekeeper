#!/usr/bin/env python
"""
Script to revoke (delete) client permissions.

Usage:
  python scripts/revoke_permission.py                           # Interactive mode
  python scripts/revoke_permission.py <permission_id>           # By permission ID
  python scripts/revoke_permission.py <client_id> <route_id>    # By client and route
"""

import sys
from dotenv import load_dotenv

from src.utils import get_db_connection


def confirm_revocation(permission, client, route) -> bool:
    """Ask user to confirm revocation."""
    print("\n" + "=" * 80)
    print("WARNING: You are about to revoke this permission")
    print("=" * 80)
    print(f"Permission ID: {permission.permission_id}")
    print(f"Client: {client.client_name} ({client.client_id})")
    print(f"Route: {route.route_pattern} ({route.service_name})")
    methods_str = ", ".join([m.value for m in permission.allowed_methods])
    print(f"Allowed methods: {methods_str}")
    print("\n" + "=" * 80)

    response = input("Type 'revoke' to confirm: ").strip()
    return response == 'revoke'


def revoke_by_permission_id(permission_id: str):
    """Revoke a permission by its ID."""
    db = get_db_connection(verbose=False)

    try:
        # Load permission
        permission = db.load_permission_by_id(permission_id)

        if not permission:
            print(f"✗ Permission not found: {permission_id}")
            return False

        # Load related entities for display
        client = db.load_client_by_id(permission.client_id)
        route = db.load_route_by_id(permission.route_id)

        if not client or not route:
            print(f"✗ Error: Could not load associated client or route")
            return False

        # Confirm revocation
        if not confirm_revocation(permission, client, route):
            print("Revocation cancelled.")
            return False

        # Delete the permission
        success = db.delete_permission(permission_id)

        if success:
            methods_str = ", ".join([m.value for m in permission.allowed_methods])
            print(f"\n✓ Permission revoked: {client.client_name} → {route.route_pattern} [{methods_str}]")
            return True
        else:
            print(f"\n✗ Failed to revoke permission")
            return False

    except Exception as e:
        print(f"\n✗ Error revoking permission: {e}")
        return False
    finally:
        db.close()


def revoke_by_client_and_route(client_id: str, route_id: str):
    """Revoke a permission by client and route IDs."""
    db = get_db_connection(verbose=False)

    try:
        # Load permission
        permission = db.load_permission_by_client_and_route(client_id, route_id)

        if not permission:
            print(f"✗ No permission found for this client/route combination")
            return False

        # Load related entities for display
        client = db.load_client_by_id(client_id)
        route = db.load_route_by_id(route_id)

        if not client or not route:
            print(f"✗ Error: Could not load client or route")
            return False

        # Confirm revocation
        if not confirm_revocation(permission, client, route):
            print("Revocation cancelled.")
            return False

        # Delete the permission
        success = db.delete_permission_by_client_and_route(client_id, route_id)

        if success:
            methods_str = ", ".join([m.value for m in permission.allowed_methods])
            print(f"\n✓ Permission revoked: {client.client_name} → {route.route_pattern} [{methods_str}]")
            return True
        else:
            print(f"\n✗ Failed to revoke permission")
            return False

    except Exception as e:
        print(f"\n✗ Error revoking permission: {e}")
        return False
    finally:
        db.close()


def revoke_interactive():
    """Interactive mode to select and revoke a permission."""
    db = get_db_connection(verbose=False)

    try:
        # Get all clients with permissions
        clients = db.load_all_clients()
        clients_with_perms = []

        for client in clients:
            perms = db.load_permissions_by_client(client.client_id)
            if perms:
                clients_with_perms.append((client, perms))

        if not clients_with_perms:
            print("No permissions found.")
            return

        print("\n" + "=" * 80)
        print("Select a permission to revoke")
        print("=" * 80)

        # Build list of all permissions
        all_permissions = []
        idx = 1

        for client, perms in clients_with_perms:
            status_indicator = "✓" if client.is_active() else "✗"
            print(f"\n{status_indicator} {client.client_name}")

            for perm in perms:
                route = db.load_route_by_id(perm.route_id)
                if route:
                    methods_str = ", ".join([m.value for m in perm.allowed_methods])
                    print(f"  {idx:2}. → {route.route_pattern:<30} [{methods_str}]")
                    all_permissions.append((perm, client, route))
                    idx += 1

        print(f"\n 0. Cancel")

        # Get user choice
        while True:
            try:
                choice = input(f"\nEnter choice (0-{len(all_permissions)}): ").strip()
                choice_idx = int(choice)

                if choice_idx == 0:
                    print("Cancelled.")
                    return

                if 1 <= choice_idx <= len(all_permissions):
                    permission, client, route = all_permissions[choice_idx - 1]

                    # Confirm and revoke
                    if confirm_revocation(permission, client, route):
                        success = db.delete_permission(permission.permission_id)
                        if success:
                            methods_str = ", ".join([m.value for m in permission.allowed_methods])
                            print(f"\n✓ Permission revoked: {client.client_name} → {route.route_pattern} [{methods_str}]")
                        else:
                            print(f"\n✗ Failed to revoke permission")
                    else:
                        print("Revocation cancelled.")
                    return

                print(f"Invalid choice. Please enter a number between 0 and {len(all_permissions)}")

            except ValueError:
                print("Invalid input. Please enter a number.")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


def main():
    """Main function."""
    load_dotenv()

    if len(sys.argv) == 1:
        # Interactive mode
        revoke_interactive()

    elif len(sys.argv) == 2:
        # Permission ID provided
        permission_id = sys.argv[1]
        revoke_by_permission_id(permission_id)

    elif len(sys.argv) == 3:
        # Client ID and Route ID provided
        client_id = sys.argv[1]
        route_id = sys.argv[2]
        revoke_by_client_and_route(client_id, route_id)

    else:
        print("Usage:")
        print("  python scripts/revoke_permission.py                           # Interactive mode")
        print("  python scripts/revoke_permission.py <permission_id>           # By permission ID")
        print("  python scripts/revoke_permission.py <client_id> <route_id>    # By client and route")
        sys.exit(1)


if __name__ == "__main__":
    main()
