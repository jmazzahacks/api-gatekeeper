#!/usr/bin/env python
"""
Interactive script to update an existing route in the API auth service.

Usage:
  python scripts/update_route.py <route_id>
  python scripts/update_route.py  # Interactive mode
"""

import sys
import time
from dotenv import load_dotenv

from src.utils import get_db_connection
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType


def get_input(prompt: str, default: str = None) -> str:
    """Get user input with optional default value."""
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "

    value = input(prompt).strip()
    if not value and default:
        return default
    return value


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no input from user."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{prompt} [{default_str}]: ").strip().lower()

    if not response:
        return default
    return response in ['y', 'yes']


def get_choice(prompt: str, choices: list, default: str = None) -> str:
    """Get a choice from a list of options."""
    print(f"\n{prompt}")
    for i, choice in enumerate(choices, 1):
        print(f"  {i}. {choice}")

    while True:
        if default:
            response = input(f"Enter choice (1-{len(choices)}) [{default}]: ").strip()
        else:
            response = input(f"Enter choice (1-{len(choices)}): ").strip()

        if not response and default:
            return default

        try:
            idx = int(response) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass

        print(f"Invalid choice. Please enter a number between 1 and {len(choices)}")


def configure_method_auth() -> MethodAuth:
    """Interactively configure authentication for an HTTP method."""
    auth_required = get_yes_no("Does this method require authentication?", default=False)

    if not auth_required:
        return MethodAuth(auth_required=False)

    auth_type_str = get_choice(
        "Select authentication type:",
        ["hmac", "api_key"]
    )
    auth_type = AuthType.HMAC if auth_type_str == "hmac" else AuthType.API_KEY

    return MethodAuth(auth_required=True, auth_type=auth_type)


def display_route(route: Route) -> None:
    """Display route details."""
    print(f"Route ID:     {route.route_id}")
    print(f"Pattern:      {route.route_pattern}")
    print(f"Domain:       {route.domain}")
    print(f"Service:      {route.service_name}")
    print("Methods:")
    for method, auth in route.methods.items():
        if auth.auth_required:
            auth_desc = f"{auth.auth_type.value} authentication required"
        else:
            auth_desc = "public (no auth)"
        print(f"  {method.value:8} -> {auth_desc}")


def update_route_interactive(route_id: str) -> bool:
    """Interactively update a route."""
    db = get_db_connection(verbose=False)

    try:
        route = db.load_route_by_id(route_id)

        if not route:
            print(f"Route not found: {route_id}")
            return False

        print("=" * 80)
        print("Update Route")
        print("=" * 80)
        print("\nCurrent route configuration:")
        print("-" * 80)
        display_route(route)
        print("-" * 80)

        print("\nPress Enter to keep current value, or enter a new value.")
        print()

        # Update route pattern
        new_pattern = get_input("Route pattern", route.route_pattern)
        if new_pattern and not new_pattern.startswith('/'):
            print("  Route pattern should start with '/'")
            new_pattern = '/' + new_pattern

        # Update domain
        new_domain = get_input("Domain", route.domain)

        # Update service name
        new_service = get_input("Service name", route.service_name)

        # Update methods
        print("\n" + "-" * 80)
        print("HTTP Method Configuration")
        print("-" * 80)

        if get_yes_no("\nReconfigure HTTP methods?", default=False):
            available_methods = [m.value for m in HttpMethod]
            new_methods = {}

            print("\nConfigure authentication for each HTTP method.")
            print("Press Enter to skip a method.\n")

            for method_name in available_methods:
                current_method = HttpMethod(method_name)
                current_auth = route.methods.get(current_method)

                if current_auth:
                    if current_auth.auth_required:
                        current_desc = f"currently: {current_auth.auth_type.value} auth"
                    else:
                        current_desc = "currently: public"
                else:
                    current_desc = "currently: not configured"

                if get_yes_no(f"Configure {method_name}? ({current_desc})", default=(current_auth is not None)):
                    print(f"\n  Configuring {method_name}:")
                    method_auth = configure_method_auth()
                    new_methods[current_method] = method_auth

                    if method_auth.auth_required:
                        print(f"  {method_name} requires {method_auth.auth_type.value} authentication")
                    else:
                        print(f"  {method_name} is public (no auth required)")

            if not new_methods:
                print("\n  Error: At least one HTTP method must be configured")
                print("  Keeping existing method configuration.")
                new_methods = route.methods
        else:
            new_methods = route.methods

        # Show summary of changes
        print("\n" + "=" * 80)
        print("Summary of Changes")
        print("=" * 80)

        changes = []
        if new_pattern != route.route_pattern:
            changes.append(f"Pattern:  {route.route_pattern} -> {new_pattern}")
        if new_domain != route.domain:
            changes.append(f"Domain:   {route.domain} -> {new_domain}")
        if new_service != route.service_name:
            changes.append(f"Service:  {route.service_name} -> {new_service}")
        if new_methods != route.methods:
            changes.append("Methods:  (reconfigured)")

        if not changes:
            print("\nNo changes detected.")
            return True

        for change in changes:
            print(f"  {change}")

        print()
        if not get_yes_no("Apply these changes?", default=True):
            print("Cancelled.")
            return False

        # Create updated route
        updated_route = Route(
            route_id=route.route_id,
            route_pattern=new_pattern,
            domain=new_domain,
            service_name=new_service,
            methods=new_methods,
            created_at=route.created_at,
            updated_at=int(time.time())
        )

        db.save_route(updated_route)
        print(f"\nRoute updated successfully: {route_id}")
        return True

    except Exception as e:
        print(f"Error updating route: {e}")
        return False
    finally:
        db.close()


def interactive_select() -> None:
    """Interactive mode to select and update a route."""
    db = get_db_connection(verbose=False)

    try:
        routes = db.load_all_routes()

        if not routes:
            print("No routes found.")
            return

        print("\n" + "=" * 80)
        print("Select a route to update")
        print("=" * 80)

        for i, route in enumerate(routes, 1):
            methods_str = ", ".join([m.value for m in route.methods.keys()])
            print(f"{i:2}. {route.route_pattern:<30} ({route.domain}) [{methods_str}]")

        print(" 0. Cancel")

        while True:
            try:
                choice = input(f"\nEnter choice (0-{len(routes)}): ").strip()
                idx = int(choice)

                if idx == 0:
                    print("Cancelled.")
                    return

                if 1 <= idx <= len(routes):
                    selected_route = routes[idx - 1]
                    db.close()
                    print()
                    update_route_interactive(selected_route.route_id)
                    return

                print(f"Invalid choice. Please enter a number between 0 and {len(routes)}")
            except ValueError:
                print("Invalid input. Please enter a number.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()


def main() -> None:
    """Main function."""
    load_dotenv()

    if len(sys.argv) > 1:
        route_id = sys.argv[1]
        update_route_interactive(route_id)
    else:
        interactive_select()


if __name__ == "__main__":
    main()
