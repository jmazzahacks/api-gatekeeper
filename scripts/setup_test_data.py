#!/usr/bin/env python
"""
Setup test data for manual testing of the API Gatekeeper service.

Creates:
- Public route (no auth)
- API key protected route
- HMAC protected route
- Test clients with credentials
- Appropriate permissions
"""
from src.utils import get_db_connection
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType
from src.models.client import Client, ClientStatus
from src.models.client_permission import ClientPermission

def main():
    print("=" * 60)
    print("Setting up test data for API Gatekeeper")
    print("=" * 60)
    print()

    # Connect to database
    db = get_db_connection()
    print("✓ Connected to database\n")

    # 1. Create public route (no authentication required)
    print("Creating public route: GET /api/public...")
    public_route = Route.create_new(
        route_pattern='/api/public',
        service_name='test-service',
        methods={
            HttpMethod.GET: MethodAuth(auth_required=False)
        }
    )
    db.save_route(public_route)
    print(f"  ✓ Route ID: {public_route.route_id}")
    print()

    # 2. Create API key protected route
    print("Creating API key protected route: GET,POST /api/protected...")
    api_key_route = Route.create_new(
        route_pattern='/api/protected',
        service_name='test-service',
        methods={
            HttpMethod.GET: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY),
            HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
        }
    )
    db.save_route(api_key_route)
    print(f"  ✓ Route ID: {api_key_route.route_id}")
    print()

    # 3. Create HMAC protected route
    print("Creating HMAC protected route: POST /api/secure...")
    hmac_route = Route.create_new(
        route_pattern='/api/secure',
        service_name='test-service',
        methods={
            HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
        }
    )
    db.save_route(hmac_route)
    print(f"  ✓ Route ID: {hmac_route.route_id}")
    print()

    # 4. Create client with API key
    print("Creating API key client...")
    api_client = Client.create_new(
        client_name='Test API Key Client',
        api_key='test-api-key-12345',
        status=ClientStatus.ACTIVE
    )
    db.save_client(api_client)
    print(f"  ✓ Client ID: {api_client.client_id}")
    print(f"  ✓ API Key: {api_client.api_key}")
    print()

    # 5. Grant API key client permission to protected route
    print("Granting permissions to API key client...")
    api_permission = ClientPermission.create_new(
        client_id=api_client.client_id,
        route_id=api_key_route.route_id,
        allowed_methods=[HttpMethod.GET, HttpMethod.POST]
    )
    db.save_permission(api_permission)
    print(f"  ✓ Permission ID: {api_permission.permission_id}")
    print()

    # 6. Create client with shared secret for HMAC
    print("Creating HMAC client...")
    hmac_client = Client.create_new(
        client_name='Test HMAC Client',
        shared_secret='hmac-shared-secret-xyz',
        status=ClientStatus.ACTIVE
    )
    db.save_client(hmac_client)
    print(f"  ✓ Client ID: {hmac_client.client_id}")
    print(f"  ✓ Shared Secret: {hmac_client.shared_secret}")
    print()

    # 7. Grant HMAC client permission to secure route
    print("Granting permissions to HMAC client...")
    hmac_permission = ClientPermission.create_new(
        client_id=hmac_client.client_id,
        route_id=hmac_route.route_id,
        allowed_methods=[HttpMethod.POST]
    )
    db.save_permission(hmac_permission)
    print(f"  ✓ Permission ID: {hmac_permission.permission_id}")
    print()

    # Print test scenarios
    print("=" * 60)
    print("Test Data Created Successfully!")
    print("=" * 60)
    print()
    print("Test Scenarios:")
    print("-" * 60)
    print()
    print("1. PUBLIC ROUTE (no auth required):")
    print("   curl -v http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/public' \\")
    print("     -H 'X-Original-Method: GET'")
    print("   Expected: 200 OK")
    print()
    print("2. PROTECTED ROUTE with API KEY:")
    print("   curl -v http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/protected' \\")
    print("     -H 'X-Original-Method: GET' \\")
    print("     -H 'Authorization: Bearer test-api-key-12345'")
    print("   Expected: 200 OK (with X-Auth-Client-ID header)")
    print()
    print("3. PROTECTED ROUTE without credentials:")
    print("   curl -v http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/protected' \\")
    print("     -H 'X-Original-Method: GET'")
    print("   Expected: 403 Forbidden")
    print()
    print("4. PROTECTED ROUTE with invalid API key:")
    print("   curl -v http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/protected' \\")
    print("     -H 'X-Original-Method: GET' \\")
    print("     -H 'Authorization: Bearer invalid-key'")
    print("   Expected: 403 Forbidden")
    print()
    print("5. HMAC PROTECTED ROUTE (requires signature):")
    print(f"   Client ID: {hmac_client.client_id}")
    print(f"   Shared Secret: {hmac_client.shared_secret}")
    print("   Use the RequestSigner utility or byteforge-hmac library")
    print("   to generate a valid HMAC signature for POST /api/secure")
    print()
    print("6. NON-EXISTENT ROUTE:")
    print("   curl -v http://localhost:7843/authz \\")
    print("     -H 'X-Original-URI: /api/nonexistent' \\")
    print("     -H 'X-Original-Method: GET'")
    print("   Expected: 403 Forbidden (no_route_match)")
    print()

if __name__ == '__main__':
    main()
