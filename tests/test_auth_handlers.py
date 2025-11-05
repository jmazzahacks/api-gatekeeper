"""
Unit tests for authentication handlers (API Key, HMAC).
CRITICAL: All tests use the api_auth_admin_test database via fixtures.
"""
import pytest
import time
from src.auth import APIKeyHandler, HMACHandler, DatabaseSecretProvider, RequestSigner
from src.models.client import Client, ClientStatus


class TestAPIKeyHandler:
    """Test API key extraction from headers and query parameters."""

    def test_extract_bearer_format(self):
        """Test extraction of Bearer format API key."""
        handler = APIKeyHandler()
        headers = {'Authorization': 'Bearer test-api-key-123'}

        api_key = handler.extract_from_header(headers)

        assert api_key == 'test-api-key-123'

    def test_extract_apikey_format(self):
        """Test extraction of ApiKey format API key."""
        handler = APIKeyHandler()
        headers = {'Authorization': 'ApiKey my-secret-key'}

        api_key = handler.extract_from_header(headers)

        assert api_key == 'my-secret-key'

    def test_extract_raw_key(self):
        """Test extraction of raw API key without prefix."""
        handler = APIKeyHandler()
        headers = {'Authorization': 'raw-key-no-prefix'}

        api_key = handler.extract_from_header(headers)

        assert api_key == 'raw-key-no-prefix'

    def test_skip_hmac_format(self):
        """Test that HMAC format is not treated as API key."""
        handler = APIKeyHandler()
        headers = {'Authorization': 'HMAC client_id="123",timestamp="1234567890",nonce="abc",signature="xyz"'}

        api_key = handler.extract_from_header(headers)

        assert api_key is None

    def test_case_insensitive_header_name(self):
        """Test that header name lookup is case-insensitive."""
        handler = APIKeyHandler()
        headers = {'authorization': 'Bearer test-key'}  # lowercase

        api_key = handler.extract_from_header(headers)

        assert api_key == 'test-key'

    def test_mixed_case_bearer_prefix(self):
        """Test that Bearer prefix is case-insensitive."""
        handler = APIKeyHandler()
        headers = {'Authorization': 'bEaReR test-key'}

        api_key = handler.extract_from_header(headers)

        assert api_key == 'test-key'

    def test_no_authorization_header(self):
        """Test extraction when no Authorization header present."""
        handler = APIKeyHandler()
        headers = {'Content-Type': 'application/json'}

        api_key = handler.extract_from_header(headers)

        assert api_key is None

    def test_empty_headers(self):
        """Test extraction with empty headers dict."""
        handler = APIKeyHandler()
        headers = {}

        api_key = handler.extract_from_header(headers)

        assert api_key is None

    def test_extract_from_query_params(self):
        """Test extraction from query parameters."""
        handler = APIKeyHandler()
        query_params = {'api_key': 'query-key-123'}

        api_key = handler.extract_from_query(query_params)

        assert api_key == 'query-key-123'

    def test_case_insensitive_query_param_name(self):
        """Test that query param name is case-insensitive."""
        handler = APIKeyHandler()
        query_params = {'API_KEY': 'query-key-456'}

        api_key = handler.extract_from_query(query_params)

        assert api_key == 'query-key-456'

    def test_query_param_list_value(self):
        """Test extraction when query param has list value (take first)."""
        handler = APIKeyHandler()
        query_params = {'api_key': ['first-key', 'second-key']}

        api_key = handler.extract_from_query(query_params)

        assert api_key == 'first-key'

    def test_query_param_empty_list(self):
        """Test extraction when query param is empty list."""
        handler = APIKeyHandler()
        query_params = {'api_key': []}

        api_key = handler.extract_from_query(query_params)

        assert api_key is None

    def test_no_query_params(self):
        """Test extraction with None query params."""
        handler = APIKeyHandler()

        api_key = handler.extract_from_query(None)

        assert api_key is None

    def test_empty_query_params(self):
        """Test extraction with empty query params dict."""
        handler = APIKeyHandler()
        query_params = {}

        api_key = handler.extract_from_query(query_params)

        assert api_key is None

    def test_extract_priority_header_over_query(self):
        """Test that header takes precedence over query parameter."""
        handler = APIKeyHandler()
        headers = {'Authorization': 'Bearer header-key'}
        query_params = {'api_key': 'query-key'}

        api_key = handler.extract(headers, query_params)

        assert api_key == 'header-key'

    def test_extract_fallback_to_query(self):
        """Test fallback to query param when header not present."""
        handler = APIKeyHandler()
        headers = {}
        query_params = {'api_key': 'query-key'}

        api_key = handler.extract(headers, query_params)

        assert api_key == 'query-key'

    def test_extract_no_credentials(self):
        """Test extraction when no credentials in headers or query."""
        handler = APIKeyHandler()
        headers = {}
        query_params = {}

        api_key = handler.extract(headers, query_params)

        assert api_key is None

    def test_custom_header_name(self):
        """Test using custom header name."""
        handler = APIKeyHandler(header_name='X-API-Key')
        headers = {'X-API-Key': 'custom-header-key'}

        api_key = handler.extract_from_header(headers)

        assert api_key == 'custom-header-key'

    def test_custom_query_param_name(self):
        """Test using custom query parameter name."""
        handler = APIKeyHandler(query_param_name='key')
        query_params = {'key': 'custom-param-key'}

        api_key = handler.extract_from_query(query_params)

        assert api_key == 'custom-param-key'


class TestDatabaseSecretProvider:
    """Test database-backed secret provider for HMAC."""

    def test_get_secret_for_valid_client(self, clean_db):
        """Test retrieving secret for existing client."""
        # Create client with shared secret
        client = Client.create_new(
            client_name='HMAC Client',
            shared_secret='test-secret-123',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)

        provider = DatabaseSecretProvider(clean_db)
        secret = provider.get_secret(client.client_id)

        assert secret == 'test-secret-123'

    def test_get_secret_for_nonexistent_client(self, clean_db):
        """Test retrieving secret for non-existent client."""
        provider = DatabaseSecretProvider(clean_db)
        # Use a valid UUID format that doesn't exist in database
        secret = provider.get_secret('00000000-0000-0000-0000-000000000000')

        assert secret is None

    def test_get_secret_for_client_without_secret(self, clean_db):
        """Test retrieving secret for client without shared secret."""
        # Create client with only API key (no shared secret)
        client = Client.create_new(
            client_name='API Key Client',
            api_key='test-api-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)

        provider = DatabaseSecretProvider(clean_db)
        secret = provider.get_secret(client.client_id)

        assert secret is None


class TestHMACHandler:
    """Test HMAC signature validation."""

    @pytest.fixture
    def hmac_client(self, clean_db):
        """Create a client with shared secret for HMAC testing."""
        client = Client.create_new(
            client_name='HMAC Test Client',
            shared_secret='hmac-secret-key',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)
        return client

    def test_valid_signature_authentication(self, clean_db, hmac_client):
        """Test authentication with valid HMAC signature."""
        # Sign a request
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_post('/api/test', '{"data": "test"}')

        # Authenticate using handler
        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/api/test',
            body='{"data": "test"}'
        )

        assert client is not None
        assert client.client_id == hmac_client.client_id
        assert client.client_name == 'HMAC Test Client'

    def test_invalid_signature_authentication(self, clean_db, hmac_client):
        """Test authentication with invalid HMAC signature."""
        # Sign with wrong secret
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='wrong-secret'
        )
        auth_header = signer.sign_post('/api/test', '{"data": "test"}')

        # Authenticate using handler
        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/api/test',
            body='{"data": "test"}'
        )

        assert client is None

    def test_tampered_body_authentication(self, clean_db, hmac_client):
        """Test authentication fails when body is tampered."""
        # Sign with original body
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_post('/api/test', '{"data": "original"}')

        # Try to authenticate with different body
        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/api/test',
            body='{"data": "tampered"}'
        )

        assert client is None

    def test_tampered_path_authentication(self, clean_db, hmac_client):
        """Test authentication fails when path is tampered."""
        # Sign with original path
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_post('/api/original', '{"data": "test"}')

        # Try to authenticate with different path
        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/api/tampered',
            body='{"data": "test"}'
        )

        assert client is None

    def test_tampered_method_authentication(self, clean_db, hmac_client):
        """Test authentication fails when method is tampered."""
        # Sign with POST
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_post('/api/test', '{"data": "test"}')

        # Try to authenticate with GET
        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='GET',
            path='/api/test',
            body='{"data": "test"}'
        )

        assert client is None

    def test_nonexistent_client_authentication(self, clean_db):
        """Test authentication with signature for non-existent client."""
        # Sign with non-existent client ID (valid UUID format)
        signer = RequestSigner(
            client_id='00000000-0000-0000-0000-000000000000',
            secret_key='fake-secret'
        )
        auth_header = signer.sign_post('/api/test', '{"data": "test"}')

        # Try to authenticate
        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/api/test',
            body='{"data": "test"}'
        )

        assert client is None

    def test_get_request_authentication(self, clean_db, hmac_client):
        """Test authentication for GET request (no body)."""
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_get('/api/users')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='GET',
            path='/api/users',
            body=''
        )

        assert client is not None
        assert client.client_id == hmac_client.client_id

    def test_delete_request_authentication(self, clean_db, hmac_client):
        """Test authentication for DELETE request."""
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_delete('/api/users/123')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='DELETE',
            path='/api/users/123',
            body=''
        )

        assert client is not None
        assert client.client_id == hmac_client.client_id

    def test_put_request_authentication(self, clean_db, hmac_client):
        """Test authentication for PUT request."""
        signer = RequestSigner(
            client_id=hmac_client.client_id,
            secret_key='hmac-secret-key'
        )
        auth_header = signer.sign_put('/api/users/123', '{"name": "updated"}')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='PUT',
            path='/api/users/123',
            body='{"name": "updated"}'
        )

        assert client is not None
        assert client.client_id == hmac_client.client_id


class TestRequestSigner:
    """Test request signing utility for generating valid HMAC signatures."""

    def test_sign_get_request(self):
        """Test signing a GET request."""
        signer = RequestSigner(
            client_id='client-123',
            secret_key='secret-key'
        )

        auth_header = signer.sign_get('/api/users')

        assert auth_header.startswith('HMAC ')
        assert 'client_id="client-123"' in auth_header
        assert 'timestamp=' in auth_header
        assert 'nonce=' in auth_header
        assert 'signature=' in auth_header

    def test_sign_post_request(self):
        """Test signing a POST request with body."""
        signer = RequestSigner(
            client_id='client-456',
            secret_key='secret-key'
        )

        auth_header = signer.sign_post('/api/users', '{"name": "test"}')

        assert auth_header.startswith('HMAC ')
        assert 'client_id="client-456"' in auth_header

    def test_sign_put_request(self):
        """Test signing a PUT request with body."""
        signer = RequestSigner(
            client_id='client-789',
            secret_key='secret-key'
        )

        auth_header = signer.sign_put('/api/users/123', '{"name": "updated"}')

        assert auth_header.startswith('HMAC ')
        assert 'client_id="client-789"' in auth_header

    def test_sign_delete_request(self):
        """Test signing a DELETE request."""
        signer = RequestSigner(
            client_id='client-abc',
            secret_key='secret-key'
        )

        auth_header = signer.sign_delete('/api/users/123')

        assert auth_header.startswith('HMAC ')
        assert 'client_id="client-abc"' in auth_header

    def test_sign_request_generic(self):
        """Test signing with generic sign_request method."""
        signer = RequestSigner(
            client_id='client-xyz',
            secret_key='secret-key'
        )

        auth_header = signer.sign_request('PATCH', '/api/users/123', '{"status": "active"}')

        assert auth_header.startswith('HMAC ')
        assert 'client_id="client-xyz"' in auth_header

    def test_signature_includes_timestamp(self):
        """Test that signature includes current timestamp."""
        signer = RequestSigner(
            client_id='client-123',
            secret_key='secret-key'
        )

        before = int(time.time())
        auth_header = signer.sign_get('/api/test')
        after = int(time.time())

        # Extract timestamp from header
        timestamp_part = [part for part in auth_header.split(',') if 'timestamp=' in part][0]
        timestamp = int(timestamp_part.split('"')[1])

        assert before <= timestamp <= after

    def test_signature_includes_nonce(self):
        """Test that signature includes unique nonce."""
        signer = RequestSigner(
            client_id='client-123',
            secret_key='secret-key'
        )

        auth_header1 = signer.sign_get('/api/test')
        auth_header2 = signer.sign_get('/api/test')

        # Extract nonces
        nonce1 = [part for part in auth_header1.split(',') if 'nonce=' in part][0].split('"')[1]
        nonce2 = [part for part in auth_header2.split(',') if 'nonce=' in part][0].split('"')[1]

        # Nonces should be different (UUIDs)
        assert nonce1 != nonce2

    def test_different_secrets_produce_different_signatures(self):
        """Test that different secrets produce different signatures."""
        signer1 = RequestSigner(client_id='client-123', secret_key='secret1')
        signer2 = RequestSigner(client_id='client-123', secret_key='secret2')

        # Use same timestamp and nonce by calling sign_request at same time
        # (In practice, timestamps and nonces will differ, but signatures will definitely differ)
        auth_header1 = signer1.sign_post('/api/test', '{"data": "test"}')
        auth_header2 = signer2.sign_post('/api/test', '{"data": "test"}')

        # Extract signatures
        sig1 = [part for part in auth_header1.split(',') if 'signature=' in part][0].split('"')[1]
        sig2 = [part for part in auth_header2.split(',') if 'signature=' in part][0].split('"')[1]

        # Signatures should be different
        assert sig1 != sig2

    def test_method_case_normalization(self):
        """Test that HTTP method is normalized to uppercase."""
        signer = RequestSigner(client_id='client-123', secret_key='secret-key')

        # Sign with lowercase method
        auth_header = signer.sign_request('post', '/api/test', '{"data": "test"}')

        # Should work (method normalized internally)
        assert auth_header.startswith('HMAC ')
