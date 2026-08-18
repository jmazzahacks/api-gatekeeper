"""
Unit tests for authentication handlers (API Key, HMAC).
CRITICAL: All tests use the api_auth_admin_test database via fixtures.
"""
import pytest
import time
from src.auth import APIKeyHandler, HMACHandler, DatabaseSecretProvider, RequestSigner
from src.auth.hmac_handler import _looks_like_uuid
from api_gatekeeper_models import Client, ClientStatus


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

    def test_get_secret_by_legacy_key_id(self, clean_db):
        """A non-UUID identifier resolves the client via legacy_key_id."""
        client = Client.create_new(
            client_name='Legacy HMAC Client',
            shared_secret='legacy-secret',
            legacy_key_id='rba-legacy-mobile',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)

        provider = DatabaseSecretProvider(clean_db)
        assert provider.get_secret('rba-legacy-mobile') == 'legacy-secret'

    def test_get_secret_unknown_legacy_key_id(self, clean_db):
        """Non-UUID identifier with no legacy_key_id match returns None."""
        provider = DatabaseSecretProvider(clean_db)
        assert provider.get_secret('never-registered-alias') is None


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


class TestLooksLikeUUID:
    """Guard the strict-canonical UUID recognizer used to dispatch HMAC lookup."""

    def test_canonical_uuid_is_accepted(self):
        assert _looks_like_uuid('c0b4b615-2381-48ff-935b-6c56596abda6') is True
        assert _looks_like_uuid('C0B4B615-2381-48FF-935B-6C56596ABDA6') is True

    def test_non_uuid_strings_rejected(self):
        assert _looks_like_uuid('podcastguru-mobile') is False
        assert _looks_like_uuid('') is False
        assert _looks_like_uuid('not-a-uuid') is False

    def test_braces_form_rejected(self):
        # uuid.UUID accepts this; we do not.
        assert _looks_like_uuid('{c0b4b615-2381-48ff-935b-6c56596abda6}') is False

    def test_urn_prefix_rejected(self):
        assert _looks_like_uuid('urn:uuid:c0b4b615-2381-48ff-935b-6c56596abda6') is False

    def test_no_dash_32hex_rejected(self):
        # uuid.UUID accepts a 32-char no-dash hex; we require the canonical form.
        assert _looks_like_uuid('c0b4b615238148ff935b6c56596abda6') is False

    def test_non_string_rejected(self):
        assert _looks_like_uuid(None) is False


class TestDatabaseSecretProviderTLSCache:
    """Verify get_secret stashes the Client for take_last_resolved to hand back."""

    def test_take_last_resolved_returns_client_after_get_secret(self, clean_db):
        client = Client.create_new(
            client_name='c', shared_secret='s',
            legacy_key_id='alias-a', status=ClientStatus.ACTIVE,
        )
        clean_db.save_client(client)

        provider = DatabaseSecretProvider(clean_db)
        secret = provider.get_secret('alias-a')
        assert secret == 's'

        # take_last_resolved returns the Client whose secret was just returned.
        stashed = provider.take_last_resolved('alias-a')
        assert stashed is not None
        assert stashed.client_id == client.client_id

    def test_take_last_resolved_clears_cache(self, clean_db):
        client = Client.create_new(
            client_name='c', shared_secret='s',
            legacy_key_id='alias-b', status=ClientStatus.ACTIVE,
        )
        clean_db.save_client(client)

        provider = DatabaseSecretProvider(clean_db)
        provider.get_secret('alias-b')

        # First call returns; second call returns None (cache cleared).
        assert provider.take_last_resolved('alias-b') is not None
        assert provider.take_last_resolved('alias-b') is None

    def test_take_last_resolved_rejects_mismatched_header(self, clean_db):
        client = Client.create_new(
            client_name='c', shared_secret='s',
            legacy_key_id='alias-c', status=ClientStatus.ACTIVE,
        )
        clean_db.save_client(client)

        provider = DatabaseSecretProvider(clean_db)
        provider.get_secret('alias-c')

        # Asking for a different header returns None (won't hand back the
        # wrong Client), and still clears whatever was stashed.
        assert provider.take_last_resolved('some-other-alias') is None
        assert provider.take_last_resolved('alias-c') is None

    def test_take_last_resolved_before_any_get_secret_returns_none(self, clean_db):
        provider = DatabaseSecretProvider(clean_db)
        assert provider.take_last_resolved('anything') is None


class TestHMACHandlerLegacyKeyIdDispatch:
    """Test HMAC handler resolves clients whose header carries a legacy string alias."""

    @pytest.fixture
    def legacy_hmac_client(self, clean_db):
        """A client with a legacy_key_id string alias."""
        client = Client.create_new(
            client_name='Podcast Guru Mobile',
            shared_secret='legacy-mobile-secret',
            legacy_key_id='podcastguru-mobile',
            status=ClientStatus.ACTIVE
        )
        clean_db.save_client(client)
        return client

    def test_legacy_string_client_id_resolves_and_authenticates(
        self, clean_db, legacy_hmac_client
    ):
        """A non-UUID client_id in the header falls back to legacy_key_id lookup."""
        signer = RequestSigner(
            client_id='podcastguru-mobile',
            secret_key='legacy-mobile-secret'
        )
        auth_header = signer.sign_post('/boost/', '{"data": "test"}')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/boost/',
            body='{"data": "test"}'
        )

        assert client is not None
        assert client.client_id == legacy_hmac_client.client_id
        assert client.legacy_key_id == 'podcastguru-mobile'

    def test_legacy_string_with_wrong_secret_denies(
        self, clean_db, legacy_hmac_client
    ):
        """Legacy alias resolves the row, but wrong secret still fails HMAC."""
        signer = RequestSigner(
            client_id='podcastguru-mobile',
            secret_key='wrong-secret'
        )
        auth_header = signer.sign_post('/boost/', '{"data": "test"}')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/boost/',
            body='{"data": "test"}'
        )

        assert client is None

    def test_unknown_legacy_string_client_id_denies(self, clean_db):
        """A non-UUID header value with no matching legacy_key_id returns None."""
        signer = RequestSigner(
            client_id='never-registered',
            secret_key='does-not-matter'
        )
        auth_header = signer.sign_post('/boost/', '{}')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/boost/',
            body='{}'
        )

        assert client is None

    def test_non_canonical_uuid_form_falls_through_to_legacy(self, clean_db):
        """
        A legacy_key_id string that happens to look uuid-ish but isn't the
        canonical 36-char hyphenated form (e.g. urn:uuid: prefix, braces,
        32-char no-dash) must be resolvable via the legacy_key_id path.
        Guards the strict-canonical UUID recognizer.
        """
        alias = 'urn:uuid:c0b4b615-2381-48ff-935b-6c56596abda6'
        client = Client.create_new(
            client_name='c', shared_secret='s',
            legacy_key_id=alias, status=ClientStatus.ACTIVE,
        )
        clean_db.save_client(client)

        signer = RequestSigner(client_id=alias, secret_key='s')
        auth_header = signer.sign_post('/x/', '{}')

        handler = HMACHandler(clean_db)
        result = handler.authenticate(
            auth_header=auth_header, method='POST', path='/x/', body='{}'
        )
        assert result is not None
        assert result.legacy_key_id == alias

    def test_uuid_shaped_header_never_touches_legacy_path(
        self, clean_db, legacy_hmac_client
    ):
        """
        Sending the header as a UUID (that happens to be the client's UUID PK)
        resolves via the canonical UUID path, not via legacy_key_id.
        Guards the "existing UUID clients are unaffected" invariant.
        """
        signer = RequestSigner(
            client_id=legacy_hmac_client.client_id,
            secret_key='legacy-mobile-secret'
        )
        auth_header = signer.sign_post('/boost/', '{"x": 1}')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header,
            method='POST',
            path='/boost/',
            body='{"x": 1}'
        )

        assert client is not None
        assert client.client_id == legacy_hmac_client.client_id

    def test_authenticate_consumes_the_tls_cache(self, clean_db, legacy_hmac_client):
        """
        On the happy path, HMACHandler.authenticate returns the Client stashed
        during get_secret and clears the TLS cache — proving it did not perform
        a second DB lookup. Guards the TOCTOU fix.
        """
        signer = RequestSigner(
            client_id='podcastguru-mobile', secret_key='legacy-mobile-secret'
        )
        auth_header = signer.sign_post('/boost/', '{}')

        handler = HMACHandler(clean_db)
        client = handler.authenticate(
            auth_header=auth_header, method='POST', path='/boost/', body='{}'
        )
        assert client is not None
        # Cache was consumed by authenticate — a second read returns None.
        assert handler.secret_provider.take_last_resolved('podcastguru-mobile') is None

    def test_unknown_uuid_header_does_not_fall_through_to_legacy(self, clean_db):
        """
        A UUID-shaped header that isn't in the DB must NOT then be tried as a
        legacy_key_id. Dispatch is one-shot on shape, not a two-step fallback.
        """
        # Register a legacy client whose legacy_key_id happens to be a valid UUID string
        uuid_shaped_alias = '00000000-0000-0000-0000-999999999999'
        client = Client.create_new(
            client_name='Alias Client',
            shared_secret='sec',
            legacy_key_id=uuid_shaped_alias,
        )
        clean_db.save_client(client)

        signer = RequestSigner(client_id=uuid_shaped_alias, secret_key='sec')
        auth_header = signer.sign_post('/x/', '{}')

        handler = HMACHandler(clean_db)
        result = handler.authenticate(
            auth_header=auth_header, method='POST', path='/x/', body='{}'
        )
        # UUID-shaped → hits UUID path → miss (that UUID isn't a real client_id).
        # No fallback to legacy_key_id lookup.
        assert result is None


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
