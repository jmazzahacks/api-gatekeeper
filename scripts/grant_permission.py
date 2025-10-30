#!/usr/bin/env python
"""
Interactive script to grant a client permission to access a route.

Usage:
  python scripts/grant_permission.py
  python scripts/grant_permission.py <client_id> <route_id>
"""

import sys
from dotenv import load_dotenv

from src.utils import get_db_connection
from src.models.client_permission import ClientPermission
from src.models.route import HttpMethod


def get_choice(prompt: str, choices: list) -> int:
    """Get a numeric choice from user."""
    while True:
        try:
            choice = input(f"{prompt} (0 to cancel): ").strip()
            idx = int(choice)
            if idx == 0:
                return 0
            if 1 <= idx <= len(choices):
                return idx
            print(f"Invalid choice. Please enter a number between 0 and {len(choices)}")
        except ValueError:
            print("Invalid input. Please enter a number.")


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no input from user."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{prompt} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ['y', 'yes']


def select_client(db) -> str:
    """Interactive client selection."""
    clients = db.load_all_clients()

    if not clients:
        print("No clients found. Create one first:")
        print("  python scripts/create_client.py")
        return None

    print("\n" + "=" * 80)
    print("Select a client")
    print("=" * 80)

    for i, client in enumerate(clients, 1):
        status_indicator = "✓" if client.is_active() else "✗"
        api_key_display = f"API:{client.api_key[:8]}..." if client.api_key else ""
        secret_display = f"HMAC:{client.shared_secret[:8]}..." if client.shared_secret else ""
        creds = ", ".join(filter(None, [api_key_display, secret_display]))
        print(f"{i:2}. {status_indicator} {client.client_name:<30} ({creds})")

    choice = get_choice(f"\nSelect client (1-{len(clients)})", clients)
    if choice == 0:
        return None

    return clients[choice - 1].client_id


def select_route(db) -> str:
    """Interactive route selection."""
    routes = db.load_all_routes()

    if not routes:
        print("No routes found. Create one first:")
        print("  python scripts/create_route.py")
        return None

    print("\n" + "=" * 80)
    print("Select a route")
    print("=" * 80)

    for i, route in enumerate(routes, 1):
        methods_str = ", ".join([m.value for m in route.methods.keys()])
        print(f"{i:2}. {route.route_pattern:<30} [{route.service_name}] Methods: {methods_str}")

    choice = get_choice(f"\nSelect route (1-{len(routes)})", routes)
    if choice == 0:
        return None

    return routes[choice - 1].route_id


def select_methods(route) -> list:
    """Interactive method selection."""
    available_methods = list(route.methods.keys())

    print("\n" + "=" * 80)
    print(f"Select HTTP methods to allow for {route.route_pattern}")
    print("=" * 80)

    for method, method_auth in route.methods.items():
        auth_info = "public" if not method_auth.auth_required else f"requires {method_auth.auth_type.value}"
        print(f"  {method.value:<8} ({auth_info})")

    print("\nWhich methods should the client be allowed to use?")

    selected_methods = []
    for method in available_methods:
        if get_yes_no(f"  Allow {method.value}?", default=True):
            selected_methods.append(method)

    return selected_methods


def grant_permission_interactive():
    """Interactive mode to grant a permission."""
    db = get_db_connection()

    try:
        print("=" * 80)
        print("Grant Client Permission to Route")
        print("=" * 80)

        # Select client
        client_id = select_client(db)
        if not client_id:
            print("Cancelled.")
            return

        client = db.load_client_by_id(client_id)

        # Select route
        route_id = select_route(db)
        if not route_id:
            print("Cancelled.")
            return

        route = db.load_route_by_id(route_id)

        # Check if permission already exists
        existing_perm = db.load_permission_by_client_and_route(client_id, route_id)
        if existing_perm:
            print(f"\n⚠ Permission already exists for this client/route combination.")
            methods_str = ", ".join([m.value for m in existing_perm.allowed_methods])
            print(f"Current allowed methods: {methods_str}")
            if not get_yes_no("\nUpdate the permission?", default=True):
                print("Cancelled.")
                return

        # Select methods
        selected_methods = select_methods(route)

        if not selected_methods:
            print("\nError: At least one method must be selected")
            return

        # Show summary
        print("\n" + "=" * 80)
        print("Summary")
        print("=" * 80)
        print(f"Client: {client.client_name}")
        print(f"Route: {route.route_pattern} ({route.service_name})")
        methods_str = ", ".join([m.value for m in selected_methods])
        print(f"Allowed methods: {methods_str}")

        if not get_yes_no("\nGrant this permission?", default=True):
            print("Cancelled.")
            return

        # Create permission
        permission = ClientPermission.create_new(
            client_id=client_id,
            route_id=route_id,
            allowed_methods=selected_methods
        )

        permission_id = db.save_permission(permission)

        print("\n" + "=" * 80)
        print("✓ Permission granted successfully!")
        print("=" * 80)
        print(f"Permission ID: {permission_id}")
        print(f"Client: {client.client_name}")
        print(f"Route: {route.route_pattern}")
        print(f"Methods: {methods_str}")
        print("\nNext steps:")
        print("  - View all permissions: python scripts/list_permissions.py")
        print("  - Test the client's access to this route")

    except Exception as e:
        print(f"\n✗ Error granting permission: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


def grant_permission_direct(client_id: str, route_id: str):
    """Grant permission with provided client and route IDs."""
    db = get_db_connection()

    try:
        # Verify client exists
        client = db.load_client_by_id(client_id)
        if not client:
            print(f"✗ Client not found: {client_id}")
            return

        # Verify route exists
        route = db.load_route_by_id(route_id)
        if not route:
            print(f"✗ Route not found: {route_id}")
            return

        # Check existing permission
        existing_perm = db.load_permission_by_client_and_route(client_id, route_id)
        if existing_perm:
            print(f"⚠ Permission already exists")
            methods_str = ", ".join([m.value for m in existing_perm.allowed_methods])
            print(f"Current allowed methods: {methods_str}")
            if not get_yes_no("Update the permission?", default=False):
                return

        # Select methods
        selected_methods = select_methods(route)

        if not selected_methods:
            print("Error: At least one method must be selected")
            return

        # Create permission
        permission = ClientPermission.create_new(
            client_id=client_id,
            route_id=route_id,
            allowed_methods=selected_methods
        )

        permission_id = db.save_permission(permission)
        methods_str = ", ".join([m.value for m in selected_methods])

        print(f"\n✓ Permission granted: {client.client_name} → {route.route_pattern} [{methods_str}]")

    except Exception as e:
        print(f"\n✗ Error granting permission: {e}")
    finally:
        db.close()


def main():
    """Main function."""
    load_dotenv()

    if len(sys.argv) == 3:
        # Client ID and Route ID provided
        client_id = sys.argv[1]
        route_id = sys.argv[2]
        grant_permission_direct(client_id, route_id)
    elif len(sys.argv) == 1:
        # Interactive mode
        grant_permission_interactive()
    else:
        print("Usage:")
        print("  python scripts/grant_permission.py                    # Interactive mode")
        print("  python scripts/grant_permission.py <client_id> <route_id>  # Direct mode")
        sys.exit(1)


if __name__ == "__main__":
    main()
