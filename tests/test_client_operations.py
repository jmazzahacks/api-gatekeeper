"""
Unit tests for client and client_permission database operations.
CRITICAL: All tests use the api_auth_admin_test database via fixtures.
"""
import pytest
import time
from src.models.client import Client, ClientStatus
from src.models.client_permission import ClientPermission
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType


class TestClientCRUD:
    """Test client CRUD operations."""

    def test_save_new_client_with_api_key(self, clean_db):
        """Test saving a new client with API key."""
        client = Client.create_new(
            client_name='Test Client',
            api_key='test-api-key-123',
            status=ClientStatus.ACTIVE
        )

        client_id = clean_db.save_client(client)

        assert client_id is not None
        assert client.client_id == client_id

        loaded = clean_db.load_client_by_id(client_id)
        assert loaded is not None
        assert loaded.client_id == client_id
        assert loaded.client_name == 'Test Client'
        assert loaded.api_key == 'test-api-key-123'
        assert loaded.shared_secret is None
        assert loaded.status == ClientStatus.ACTIVE

    def test_save_new_client_with_shared_secret(self, clean_db):
        """Test saving a new client with shared secret."""
        client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='super-secret-key-456',
            status=ClientStatus.ACTIVE
        )

        client_id = clean_db.save_client(client)

        loaded = clean_db.load_client_by_id(client_id)
        assert loaded is not None
        assert loaded.shared_secret == 'super-secret-key-456'
        assert loaded.api_key is None
        assert loaded.has_shared_secret() is True
        assert loaded.has_api_key() is False

    def test_save_client_with_both_credentials(self, clean_db):
        """Test saving a client with both API key and shared secret."""
        client = Client.create_new(
            client_name='Full Client',
            api_key='api-key-789',
            shared_secret='shared-secret-789',
            status=ClientStatus.ACTIVE
        )

        client_id = clean_db.save_client(client)

        loaded = clean_db.load_client_by_id(client_id)
        assert loaded.api_key == 'api-key-789'
        assert loaded.shared_secret == 'shared-secret-789'
        assert loaded.has_api_key() is True
        assert loaded.has_shared_secret() is True

    def test_save_client_upsert_updates_existing(self, clean_db):
        """Test that saving an existing client updates it (upsert behavior)."""
        client = Client.create_new(
            client_name='Original Name',
            api_key='original-key'
        )
        client_id = clean_db.save_client(client)

        time.sleep(1)

        # Update client with same ID
        updated_client = Client.create_new(
            client_name='Updated Name',
            api_key='updated-key',
            status=ClientStatus.SUSPENDED,
            client_id=client_id
        )
        clean_db.save_client(updated_client)

        loaded = clean_db.load_client_by_id(client_id)
        assert loaded.client_name == 'Updated Name'
        assert loaded.api_key == 'updated-key'
        assert loaded.status == ClientStatus.SUSPENDED
        assert loaded.updated_at > loaded.created_at

    def test_load_client_by_id_not_found(self, clean_db):
        """Test loading a client that doesn't exist."""
        loaded = clean_db.load_client_by_id('00000000-0000-0000-0000-000000000000')
        assert loaded is None

    def test_load_client_by_api_key(self, clean_db):
        """Test loading a client by API key."""
        client = Client.create_new(
            client_name='API Client',
            api_key='unique-api-key'
        )
        clean_db.save_client(client)

        loaded = clean_db.load_client_by_api_key('unique-api-key')
        assert loaded is not None
        assert loaded.client_name == 'API Client'
        assert loaded.api_key == 'unique-api-key'

    def test_load_client_by_api_key_not_found(self, clean_db):
        """Test loading by API key that doesn't exist."""
        loaded = clean_db.load_client_by_api_key('nonexistent-key')
        assert loaded is None

    def test_load_client_by_shared_secret(self, clean_db):
        """Test loading a client by shared secret."""
        client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='unique-shared-secret'
        )
        clean_db.save_client(client)

        loaded = clean_db.load_client_by_shared_secret('unique-shared-secret')
        assert loaded is not None
        assert loaded.client_name == 'HMAC Client'
        assert loaded.shared_secret == 'unique-shared-secret'

    def test_load_client_by_shared_secret_not_found(self, clean_db):
        """Test loading by shared secret that doesn't exist."""
        loaded = clean_db.load_client_by_shared_secret('nonexistent-secret')
        assert loaded is None

    def test_load_all_clients(self, clean_db):
        """Test loading all clients."""
        client1 = Client.create_new(client_name='Client A', api_key='key-a')
        client2 = Client.create_new(client_name='Client B', api_key='key-b')
        client3 = Client.create_new(client_name='Client C', shared_secret='secret-c')

        clean_db.save_client(client1)
        clean_db.save_client(client2)
        clean_db.save_client(client3)

        clients = clean_db.load_all_clients()
        assert len(clients) == 3
        # Check they're sorted by client_name
        assert clients[0].client_name == 'Client A'
        assert clients[1].client_name == 'Client B'
        assert clients[2].client_name == 'Client C'

    def test_load_all_clients_empty(self, clean_db):
        """Test loading all clients when none exist."""
        clients = clean_db.load_all_clients()
        assert clients == []

    def test_delete_client(self, clean_db):
        """Test deleting a client."""
        client = Client.create_new(client_name='To Delete', api_key='delete-me')
        client_id = clean_db.save_client(client)

        # Verify it exists
        loaded = clean_db.load_client_by_id(client_id)
        assert loaded is not None

        # Delete it
        result = clean_db.delete_client(client_id)
        assert result is True

        # Verify it's gone
        loaded = clean_db.load_client_by_id(client_id)
        assert loaded is None

    def test_delete_client_not_found(self, clean_db):
        """Test deleting a client that doesn't exist."""
        result = clean_db.delete_client('00000000-0000-0000-0000-000000000000')
        assert result is False

    def test_client_status_filtering(self, clean_db):
        """Test that client status is properly stored and retrieved."""
        active = Client.create_new(client_name='Active', api_key='key-1', status=ClientStatus.ACTIVE)
        suspended = Client.create_new(client_name='Suspended', api_key='key-2', status=ClientStatus.SUSPENDED)
        revoked = Client.create_new(client_name='Revoked', api_key='key-3', status=ClientStatus.REVOKED)

        clean_db.save_client(active)
        clean_db.save_client(suspended)
        clean_db.save_client(revoked)

        loaded_active = clean_db.load_client_by_api_key('key-1')
        loaded_suspended = clean_db.load_client_by_api_key('key-2')
        loaded_revoked = clean_db.load_client_by_api_key('key-3')

        assert loaded_active.status == ClientStatus.ACTIVE
        assert loaded_active.is_active() is True
        assert loaded_suspended.status == ClientStatus.SUSPENDED
        assert loaded_suspended.is_active() is False
        assert loaded_revoked.status == ClientStatus.REVOKED
        assert loaded_revoked.is_active() is False


class TestClientPermissionCRUD:
    """Test client permission CRUD operations."""

    @pytest.fixture
    def sample_client(self, clean_db):
        """Create a sample client for permission tests."""
        client = Client.create_new(client_name='Test Client', api_key='test-key')
        clean_db.save_client(client)
        return client

    @pytest.fixture
    def sample_route(self, clean_db):
        """Create a sample route for permission tests."""
        route = Route.create_new(
            route_pattern='/api/test',
            domain='*',
            service_name='test-service',
            methods={
                HttpMethod.GET: MethodAuth(auth_required=False),
                HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)
            }
        )
        clean_db.save_route(route)
        return route

    def test_save_new_permission(self, clean_db, sample_client, sample_route):
        """Test saving a new client permission."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET, HttpMethod.POST]
        )

        perm_id = clean_db.save_permission(permission)

        assert perm_id is not None
        assert permission.permission_id == perm_id

        loaded = clean_db.load_permission_by_id(perm_id)
        assert loaded is not None
        assert loaded.permission_id == perm_id
        assert loaded.client_id == sample_client.client_id
        assert loaded.route_id == sample_route.route_id
        assert len(loaded.allowed_methods) == 2
        assert HttpMethod.GET in loaded.allowed_methods
        assert HttpMethod.POST in loaded.allowed_methods

    def test_save_permission_upsert_on_duplicate_client_route(self, clean_db, sample_client, sample_route):
        """Test that saving permission for same client/route updates allowed methods."""
        permission1 = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        perm_id1 = clean_db.save_permission(permission1)

        # Try to create another permission for same client/route with different methods
        permission2 = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE]
        )
        perm_id2 = clean_db.save_permission(permission2)

        # Should update the existing permission due to UNIQUE constraint
        assert perm_id2 is not None

        # Load and verify the methods were updated
        loaded = clean_db.load_permission_by_client_and_route(
            sample_client.client_id,
            sample_route.route_id
        )
        assert loaded is not None
        assert len(loaded.allowed_methods) == 3

    def test_load_permission_by_id_not_found(self, clean_db):
        """Test loading a permission that doesn't exist."""
        loaded = clean_db.load_permission_by_id('00000000-0000-0000-0000-000000000000')
        assert loaded is None

    def test_load_permissions_by_client(self, clean_db, sample_client):
        """Test loading all permissions for a client."""
        # Create multiple routes
        route1 = Route.create_new(
            route_pattern='/api/route1',
            domain='*',
            service_name='service1',
            methods={HttpMethod.GET: MethodAuth(auth_required=False)}
        )
        route2 = Route.create_new(
            route_pattern='/api/route2',
            domain='*',
            service_name='service2',
            methods={HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.API_KEY)}
        )
        clean_db.save_route(route1)
        clean_db.save_route(route2)

        # Create permissions
        perm1 = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=route1.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        perm2 = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=route2.route_id,
            allowed_methods=[HttpMethod.POST]
        )
        clean_db.save_permission(perm1)
        clean_db.save_permission(perm2)

        # Load all permissions for client
        permissions = clean_db.load_permissions_by_client(sample_client.client_id)
        assert len(permissions) == 2
        route_ids = [p.route_id for p in permissions]
        assert route1.route_id in route_ids
        assert route2.route_id in route_ids

    def test_load_permissions_by_client_empty(self, clean_db, sample_client):
        """Test loading permissions for a client with no permissions."""
        permissions = clean_db.load_permissions_by_client(sample_client.client_id)
        assert permissions == []

    def test_load_permissions_by_route(self, clean_db, sample_route):
        """Test loading all permissions for a route."""
        # Create multiple clients
        client1 = Client.create_new(client_name='Client 1', api_key='key-1')
        client2 = Client.create_new(client_name='Client 2', api_key='key-2')
        clean_db.save_client(client1)
        clean_db.save_client(client2)

        # Create permissions
        perm1 = ClientPermission.create_new(
            client_id=client1.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        perm2 = ClientPermission.create_new(
            client_id=client2.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.POST]
        )
        clean_db.save_permission(perm1)
        clean_db.save_permission(perm2)

        # Load all permissions for route
        permissions = clean_db.load_permissions_by_route(sample_route.route_id)
        assert len(permissions) == 2
        client_ids = [p.client_id for p in permissions]
        assert client1.client_id in client_ids
        assert client2.client_id in client_ids

    def test_load_permissions_by_route_empty(self, clean_db, sample_route):
        """Test loading permissions for a route with no permissions."""
        permissions = clean_db.load_permissions_by_route(sample_route.route_id)
        assert permissions == []

    def test_load_permission_by_client_and_route(self, clean_db, sample_client, sample_route):
        """Test loading a specific permission by client and route."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET, HttpMethod.POST]
        )
        clean_db.save_permission(permission)

        loaded = clean_db.load_permission_by_client_and_route(
            sample_client.client_id,
            sample_route.route_id
        )
        assert loaded is not None
        assert loaded.client_id == sample_client.client_id
        assert loaded.route_id == sample_route.route_id

    def test_load_permission_by_client_and_route_not_found(self, clean_db, sample_client, sample_route):
        """Test loading permission when client/route combination doesn't exist."""
        loaded = clean_db.load_permission_by_client_and_route(
            sample_client.client_id,
            sample_route.route_id
        )
        assert loaded is None

    def test_delete_permission(self, clean_db, sample_client, sample_route):
        """Test deleting a permission."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        perm_id = clean_db.save_permission(permission)

        # Verify it exists
        loaded = clean_db.load_permission_by_id(perm_id)
        assert loaded is not None

        # Delete it
        result = clean_db.delete_permission(perm_id)
        assert result is True

        # Verify it's gone
        loaded = clean_db.load_permission_by_id(perm_id)
        assert loaded is None

    def test_delete_permission_not_found(self, clean_db):
        """Test deleting a permission that doesn't exist."""
        result = clean_db.delete_permission('00000000-0000-0000-0000-000000000000')
        assert result is False

    def test_delete_permission_by_client_and_route(self, clean_db, sample_client, sample_route):
        """Test deleting a permission by client and route IDs."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        clean_db.save_permission(permission)

        # Delete by client and route
        result = clean_db.delete_permission_by_client_and_route(
            sample_client.client_id,
            sample_route.route_id
        )
        assert result is True

        # Verify it's gone
        loaded = clean_db.load_permission_by_client_and_route(
            sample_client.client_id,
            sample_route.route_id
        )
        assert loaded is None

    def test_delete_permission_by_client_and_route_not_found(self, clean_db, sample_client, sample_route):
        """Test deleting permission when client/route combination doesn't exist."""
        result = clean_db.delete_permission_by_client_and_route(
            sample_client.client_id,
            sample_route.route_id
        )
        assert result is False

    def test_cascade_delete_permissions_when_client_deleted(self, clean_db, sample_client, sample_route):
        """Test that deleting a client cascades to delete permissions."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        perm_id = clean_db.save_permission(permission)

        # Verify permission exists
        loaded_perm = clean_db.load_permission_by_id(perm_id)
        assert loaded_perm is not None

        # Delete client
        clean_db.delete_client(sample_client.client_id)

        # Verify permission was cascade deleted
        loaded_perm = clean_db.load_permission_by_id(perm_id)
        assert loaded_perm is None

    def test_cascade_delete_permissions_when_route_deleted(self, clean_db, sample_client, sample_route):
        """Test that deleting a route cascades to delete permissions."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET]
        )
        perm_id = clean_db.save_permission(permission)

        # Verify permission exists
        loaded_perm = clean_db.load_permission_by_id(perm_id)
        assert loaded_perm is not None

        # Delete route
        clean_db.delete_route(sample_route.route_id)

        # Verify permission was cascade deleted
        loaded_perm = clean_db.load_permission_by_id(perm_id)
        assert loaded_perm is None

    def test_permission_allows_method(self, clean_db, sample_client, sample_route):
        """Test the allows_method helper on ClientPermission."""
        permission = ClientPermission.create_new(
            client_id=sample_client.client_id,
            route_id=sample_route.route_id,
            allowed_methods=[HttpMethod.GET, HttpMethod.POST]
        )

        assert permission.allows_method(HttpMethod.GET) is True
        assert permission.allows_method(HttpMethod.POST) is True
        assert permission.allows_method(HttpMethod.DELETE) is False
        assert permission.allows_method(HttpMethod.PUT) is False
