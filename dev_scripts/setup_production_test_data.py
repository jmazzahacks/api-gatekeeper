#!/usr/bin/env python
"""
Production Test Data Setup Script

Creates test routes, clients, and permissions on the production server
for verifying the API Gatekeeper deployment.

Usage:
    python dev_scripts/setup_production_test_data.py

This script creates:
1. Public test route (GET /api/test/public)
2. API key protected route (GET,POST /api/test/protected)
3. HMAC protected route (POST /api/test/secure)
4. Test client with API key
5. Test client with HMAC shared secret
6. Appropriate permissions

After running, you can test with:
- Public: curl http://your-server:7843/authz -H "X-Original-URI: /api/test/public" -H "X-Original-Method: GET"
- API Key: curl http://your-server:7843/authz -H "X-Original-URI: /api/test/protected" -H "X-Original-Method: GET" -H "Authorization: Bearer test-api-key-production"
"""

import sys
from src.utils import get_db_connection
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType
from src.models.client import Client, ClientStatus
from src.models.client_permission import ClientPermission


def main():
    """Set up test data for production server."""
    print("=" * 80)
    print("API Gatekeeper - Production Test Data Setup")
    print("=" * 80)
    print()

    # Connect to database
    db = get_db_connection(verbose=True)

    print("Creating test routes...")
    print("-" * 80)

    # 1. Public route - no authentication required
    public_route = Route.create_new(
        route_pattern='/api/test/public',
        service_name='test-service',
        methods={
            HttpMethod.GET: MethodAuth(auth_required=False)
        }
    )
    db.save_route(public_route)
    print(f"✓ Created public route: GET /api/test/public")
    print(f"  Route ID: {public_route.route_id}")

    # 2. API key protected route
    apikey_route = Route.create_new(
        route_pattern='/api/test/protected',
        service_name='test-service',
        methods={
            HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
            HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
        }
    )
    db.save_route(apikey_route)
    print(f"✓ Created API key protected route: GET,POST /api/test/protected")
    print(f"  Route ID: {apikey_route.route_id}")

    # 3. HMAC protected route
    hmac_route = Route.create_new(
        route_pattern='/api/test/secure',
        service_name='test-service',
        methods={
            HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
        }
    )
    db.save_route(hmac_route)
    print(f"✓ Created HMAC protected route: POST /api/test/secure")
    print(f"  Route ID: {hmac_route.route_id}")

    print()
    print("Creating test clients...")
    print("-" * 80)

    # 4. API key client
    apikey_client = Client.create_new(
        client_name='Production Test Client (API Key)',
        api_key='test-api-key-production',
        status=ClientStatus.ACTIVE
    )
    db.save_client(apikey_client)
    print(f"✓ Created API key client: {apikey_client.client_name}")
    print(f"  Client ID: {apikey_client.client_id}")
    print(f"  API Key: {apikey_client.api_key}")

    # 5. HMAC client
    hmac_client = Client.create_new(
        client_name='Production Test Client (HMAC)',
        shared_secret='test-hmac-secret-production',
        status=ClientStatus.ACTIVE
    )
    db.save_client(hmac_client)
    print(f"✓ Created HMAC client: {hmac_client.client_name}")
    print(f"  Client ID: {hmac_client.client_id}")
    print(f"  Shared Secret: {hmac_client.shared_secret}")

    print()
    print("Granting permissions...")
    print("-" * 80)

    # 6. Grant API key client access to protected route
    apikey_permission = ClientPermission.create_new(
        client_id=apikey_client.client_id,
        route_id=apikey_route.route_id,
        allowed_methods=[HttpMethod.GET, HttpMethod.POST]
    )
    db.save_permission(apikey_permission)
    print(f"✓ Granted API key client access to /api/test/protected (GET, POST)")

    # 7. Grant HMAC client access to secure route
    hmac_permission = ClientPermission.create_new(
        client_id=hmac_client.client_id,
        route_id=hmac_route.route_id,
        allowed_methods=[HttpMethod.POST]
    )
    db.save_permission(hmac_permission)
    print(f"✓ Granted HMAC client access to /api/test/secure (POST)")

    print()
    print("=" * 80)
    print("Test data setup complete!")
    print("=" * 80)
    print()

    print("Test Commands:")
    print("-" * 80)
    print()

    print("1. Test Public Route (should return 200):")
    print("   curl -i http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/test/public' \\")
    print("     -H 'X-Original-Method: GET'")
    print()

    print("2. Test Protected Route WITHOUT credentials (should return 403):")
    print("   curl -i http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/test/protected' \\")
    print("     -H 'X-Original-Method: GET'")
    print()

    print("3. Test Protected Route WITH API key (should return 200):")
    print("   curl -i http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/test/protected' \\")
    print("     -H 'X-Original-Method: GET' \\")
    print("     -H 'Authorization: Bearer test-api-key-production'")
    print()

    print("4. Test Protected Route with API key in query param (should return 200):")
    print("   curl -i http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/test/protected?api_key=test-api-key-production' \\")
    print("     -H 'X-Original-Method: GET'")
    print()

    print("5. Test HMAC Protected Route (requires request signing):")
    print("   # Use the RequestSigner from src/auth/request_signer.py")
    print(f"   # Client ID: {hmac_client.client_id}")
    print("   # Secret: test-hmac-secret-production")
    print()

    print("6. Test Health Endpoint:")
    print("   curl -i http://localhost:7843/health")
    print()

    print("7. Test Metrics Endpoint:")
    print("   curl -i http://localhost:7843/metrics | head -50")
    print()

    print("=" * 80)
    print("Summary of Test Resources Created:")
    print("=" * 80)
    print(f"Routes: 3")
    print(f"  - Public: /api/test/public")
    print(f"  - API Key: /api/test/protected")
    print(f"  - HMAC: /api/test/secure")
    print()
    print(f"Clients: 2")
    print(f"  - API Key Client: {apikey_client.client_id}")
    print(f"  - HMAC Client: {hmac_client.client_id}")
    print()
    print(f"Permissions: 2")
    print()
    print("Replace 'localhost:7843' with your production server hostname/IP")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError during setup: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
