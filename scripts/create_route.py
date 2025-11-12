#!/usr/bin/env python
"""
Interactive script to create a new route in the API auth service.

Usage:
  python scripts/create_route.py
"""

import sys
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


def main():
    """Main function to create a route interactively."""
    load_dotenv()

    print("=" * 60)
    print("Create New Route")
    print("=" * 60)
    print()

    # Connect to database
    db = get_db_connection()

    # Get route information
    print("Route Information")
    print("-" * 60)

    route_pattern = get_input("Route pattern (e.g., /api/users or /api/users/*)")
    while not route_pattern:
        print("Route pattern is required")
        route_pattern = get_input("Route pattern (e.g., /api/users or /api/users/*)")

    if not route_pattern.startswith('/'):
        print("⚠️  Route pattern should start with '/'")
        route_pattern = '/' + route_pattern

    print("\nDomain: Specify which domain(s) this route applies to")
    print("  - Enter a domain like 'api.example.com' for exact match")
    print("  - Enter '*.example.com' to match all subdomains")
    print("  - Enter '*' to match any domain")
    domain = get_input("Domain (e.g., api.example.com or * for any)")
    while not domain:
        print("Domain is required")
        domain = get_input("Domain (e.g., api.example.com or * for any)")

    service_name = get_input("Service name (e.g., user-service)")
    while not service_name:
        print("Service name is required")
        service_name = get_input("Service name (e.g., user-service)")

    # Configure HTTP methods
    print("\n" + "=" * 60)
    print("HTTP Method Configuration")
    print("=" * 60)

    available_methods = [m.value for m in HttpMethod]
    methods = {}

    print("\nConfigure authentication for each HTTP method.")
    print("Press Enter to skip a method.\n")

    for method_name in available_methods:
        if get_yes_no(f"Configure {method_name}?", default=(method_name in ['GET', 'POST'])):
            print(f"\n  Configuring {method_name}:")
            method_auth = configure_method_auth()
            methods[HttpMethod(method_name)] = method_auth

            if method_auth.auth_required:
                print(f"  ✓ {method_name} requires {method_auth.auth_type.value} authentication")
            else:
                print(f"  ✓ {method_name} is public (no auth required)")

    if not methods:
        print("\n⚠️  Error: At least one HTTP method must be configured")
        db.close()
        sys.exit(1)

    # Create the route
    print("\n" + "=" * 60)
    print("Route Summary")
    print("=" * 60)
    print(f"Route Pattern:  {route_pattern}")
    print(f"Domain:         {domain}")
    print(f"Service Name:   {service_name}")
    print(f"\nHTTP Methods:")
    for method, auth in methods.items():
        if auth.auth_required:
            print(f"  {method.value:8} → {auth.auth_type.value} authentication required")
        else:
            print(f"  {method.value:8} → public (no auth)")

    print("\n" + "=" * 60)

    if not get_yes_no("Save this route?", default=True):
        print("Cancelled.")
        db.close()
        sys.exit(0)

    try:
        route = Route.create_new(
            route_pattern=route_pattern,
            domain=domain,
            service_name=service_name,
            methods=methods
        )
        route_id = db.save_route(route)
        print(f"\n✓ Route saved successfully with ID: {route_id}")

        # Show matching example
        if route_pattern.endswith('/*'):
            example_path = route_pattern.replace('/*', '/123')
        else:
            example_path = route_pattern

        domain_display = domain if domain != '*' else 'any domain'
        print(f"\nExample: This route will match requests to:")
        print(f"  http://{domain_display}{example_path}")

    except Exception as e:
        print(f"\n✗ Error saving route: {e}")
        db.close()
        sys.exit(1)

    db.close()


if __name__ == "__main__":
    main()
