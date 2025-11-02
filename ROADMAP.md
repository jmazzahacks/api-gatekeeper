# Development Roadmap

This document outlines the development plan for completing the API Gatekeeper system.

## Current Status

### ✅ Completed (Foundation)

- **Database Schema**: Routes, clients, and permissions tables with proper indexes and constraints
- **Data Models**: Route, Client, ClientPermission with validation and serialization
- **Database Driver**: Full CRUD operations with connection pooling
- **Management Scripts**: 9 interactive CLI tools for complete system configuration
  - Route management (create, list, delete)
  - Client management (create, list, delete)
  - Permission management (grant, list, revoke)
- **Test Suite**: 74 comprehensive unit tests with test database isolation
- **Documentation**: README, ARCHITECTURE, DATABASE_SETUP guides

**Bottom line**: Configuration layer is complete. Can define routes, create clients, and grant permissions.

---

## Phase 1: Authorization Engine (Core Logic) 🎯 **CURRENT PHASE**

**Goal**: Build the decision-making logic that determines allow/deny for requests

**Why this phase**: This is the core of the system. Can be fully unit tested without HTTP complexity.

### Components to Build

#### 1. Auth Result Model (`src/auth/models.py`)

```python
@dataclass
class AuthResult:
    """Result of an authorization check."""
    allowed: bool
    reason: str  # "no_auth_required", "authenticated", "invalid_credentials", etc.
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    matched_route_id: Optional[str] = None
```

**Purpose**: Standardized response from authorizer with all context needed for logging/debugging.

#### 2. Authorizer Class (`src/auth/authorizer.py`)

```python
class Authorizer:
    """Main authorization engine."""

    def __init__(self, db: AuthServiceDB):
        self.db = db

    def authorize_request(
        self,
        path: str,
        method: HttpMethod,
        api_key: Optional[str] = None,
        hmac_signature: Optional[str] = None
    ) -> AuthResult:
        """
        Determine if a request should be allowed.

        Flow:
        1. Match request path to routes
        2. Check if route requires auth for this method
        3. If no auth required -> allow
        4. If auth required -> validate credentials
        5. Look up client and check status
        6. Verify client has permission for route+method
        7. Return result
        """
```

**Key methods**:
- `_match_routes(path)` - Find matching routes (exact and wildcard)
- `_select_best_route(routes)` - Handle multiple matches (priority rules)
- `_authenticate_client(api_key, hmac_sig)` - Validate credentials
- `_check_permission(client, route, method)` - Verify access

#### 3. Route Matching Logic

**Requirements**:
- Exact match takes priority over wildcard
- `/api/users/123` matches `/api/users/123` (exact)
- `/api/users/123` matches `/api/users/*` (wildcard)
- If multiple wildcards match, choose most specific (longest prefix)

**Edge cases**:
- No routes match -> deny
- Multiple exact matches -> error (should not happen with unique patterns)
- Route exists but method not configured -> deny

#### 4. Authentication Logic

**For API Key**:
```python
if api_key:
    client = db.load_client_by_api_key(api_key)
    if not client:
        return AuthResult(False, "invalid_api_key")
    if not client.is_active():
        return AuthResult(False, f"client_{client.status.value}")
```

**For HMAC** (stub for now, real crypto in Phase 2):
```python
if hmac_signature:
    # Phase 1: Just check if signature exists and client found
    # Phase 2: Validate actual signature
    client = db.load_client_by_shared_secret(shared_secret)
```

#### 5. Permission Checking Logic

```python
def _check_permission(self, client, route, method):
    permission = db.load_permission_by_client_and_route(
        client.client_id,
        route.route_id
    )

    if not permission:
        return AuthResult(False, "no_permission")

    if not permission.allows_method(method):
        return AuthResult(False, "method_not_allowed")

    return AuthResult(
        True,
        "authenticated",
        client_id=client.client_id,
        client_name=client.client_name
    )
```

### Tests to Write

**Route Matching** (`tests/test_authorizer_route_matching.py`):
- Exact match
- Wildcard match
- No match
- Multiple matches (priority)
- Edge cases (trailing slashes, etc.)

**Public Routes** (`tests/test_authorizer_public.py`):
- GET request to public route (no credentials) -> allow
- POST to route with no POST configured -> deny
- Mixed public/protected methods on same route

**Authenticated Access** (`tests/test_authorizer_authenticated.py`):
- Valid API key with permission -> allow
- Valid API key without permission -> deny
- Invalid API key -> deny
- Suspended client -> deny
- Revoked client -> deny
- Wrong HTTP method -> deny

**Edge Cases** (`tests/test_authorizer_edge_cases.py`):
- No routes configured
- Client exists but route doesn't
- Route exists but client doesn't
- Both API key and HMAC provided (which takes precedence?)
- Neither credential provided for protected route

**Target**: 30+ tests covering all scenarios

### Success Criteria

- [ ] AuthResult model created
- [ ] Authorizer class implemented
- [ ] Route matching logic working (exact and wildcard)
- [ ] Public route handling (no auth required)
- [ ] API key authentication (basic validation)
- [ ] Client status checking (active/suspended/revoked)
- [ ] Permission verification (client + route + method)
- [ ] Comprehensive test suite (30+ tests, all passing)
- [ ] Integration with existing database models

### Estimated Effort

**Development**: 4-6 hours
**Testing**: 3-4 hours
**Total**: ~1 day

---

## Phase 2: Authentication Handlers (Crypto & Validation)

**Goal**: Implement real credential validation with cryptographic signatures

**Why this phase**: Replace authorization engine stubs with actual HMAC validation.

### Components to Build

#### 1. API Key Handler (`src/auth/api_key_handler.py`)

```python
class APIKeyHandler:
    """Extract and validate API keys from requests."""

    def extract_from_header(self, headers: dict) -> Optional[str]:
        """Extract API key from Authorization header."""
        # Support: "Bearer <key>" or "ApiKey <key>"

    def extract_from_query(self, query_params: dict) -> Optional[str]:
        """Extract API key from query parameter."""
        # Support: ?api_key=<key>
```

**Configuration**:
- Header name (default: `Authorization`)
- Query param name (default: `api_key`)
- Format (Bearer, ApiKey, or raw)

#### 2. HMAC Handler (`src/auth/hmac_handler.py`)

```python
@dataclass
class HMACComponents:
    """Components of an HMAC signature."""
    signature: str
    timestamp: int
    method: str
    path: str
    body_hash: str  # SHA256 of request body

class HMACHandler:
    """Validate HMAC signatures."""

    def extract_components(self, headers: dict) -> Optional[HMACComponents]:
        """Extract HMAC signature components from headers."""

    def compute_signature(
        self,
        secret: str,
        method: str,
        path: str,
        timestamp: int,
        body_hash: str
    ) -> str:
        """Compute HMAC-SHA256 signature."""
        # String to sign: "{method}\n{path}\n{timestamp}\n{body_hash}"

    def validate_timestamp(self, timestamp: int, tolerance_seconds: int = 300) -> bool:
        """Check if timestamp is within acceptable range."""
        # Prevents replay attacks

    def validate_signature(
        self,
        signature: str,
        secret: str,
        method: str,
        path: str,
        timestamp: int,
        body_hash: str
    ) -> bool:
        """Validate HMAC signature matches expected."""
```

**Security features**:
- Timestamp validation (5-minute tolerance by default)
- Constant-time comparison (prevent timing attacks)
- Body hash verification (prevent tampering)

#### 3. Request Signer (`src/auth/request_signer.py`)

```python
class RequestSigner:
    """Client-side request signing utility (for testing)."""

    def sign_request(
        self,
        secret: str,
        method: str,
        path: str,
        body: Optional[bytes] = None
    ) -> dict:
        """
        Generate headers for HMAC-signed request.

        Returns:
            {
                'X-Signature': '<hmac_signature>',
                'X-Timestamp': '<unix_timestamp>',
                'X-Body-Hash': '<sha256_hash>'
            }
        """
```

**Usage** (in tests):
```python
signer = RequestSigner()
headers = signer.sign_request(
    secret="client_shared_secret",
    method="POST",
    path="/api/users",
    body=b'{"name": "John"}'
)
# Use headers in test requests
```

#### 4. Configuration (`src/auth/config.py`)

```python
@dataclass
class AuthConfig:
    """Authentication configuration."""
    api_key_header_name: str = "Authorization"
    api_key_query_param: str = "api_key"
    hmac_signature_header: str = "X-Signature"
    hmac_timestamp_header: str = "X-Timestamp"
    hmac_body_hash_header: str = "X-Body-Hash"
    hmac_tolerance_seconds: int = 300
```

### Tests to Write

**API Key Extraction**:
- From Authorization header (Bearer)
- From query parameter
- Missing key
- Malformed header

**HMAC Validation**:
- Valid signature -> success
- Invalid signature -> failure
- Expired timestamp -> failure
- Replay attack (same timestamp twice)
- Body tampering detection
- Missing components

**Request Signing** (for testing):
- Generate valid signatures
- Verify against HMAC handler

### Success Criteria

- [ ] API key extraction from headers and query params
- [ ] HMAC signature computation (HMAC-SHA256)
- [ ] Timestamp validation with configurable tolerance
- [ ] Body hash validation
- [ ] Constant-time signature comparison
- [ ] Request signing utility for tests
- [ ] Integration with authorizer
- [ ] Test suite for all authentication paths

### Estimated Effort

**Development**: 4-5 hours
**Testing**: 3-4 hours
**Total**: ~1 day

---

## Phase 3: Flask HTTP Endpoint (Nginx Integration)

**Goal**: Create the web service nginx calls for auth decisions

### Components to Build

#### 1. Flask Application (`src/app.py`)

```python
from flask import Flask, request
from src.auth.authorizer import Authorizer
from src.utils import get_db_connection

app = Flask(__name__)
db = get_db_connection()
authorizer = Authorizer(db)

@app.route('/auth', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def auth_request():
    """
    Nginx auth_request endpoint.

    Nginx passes:
    - X-Original-URI: The original request path
    - X-Original-Method: The original HTTP method
    - Authorization: Client's auth header (if present)
    - X-Signature, X-Timestamp: HMAC components (if present)

    Response:
    - 200 OK: Allow request (+ set X-Auth-Client-ID header)
    - 403 Forbidden: Deny request
    - 500 Internal Server Error: System error
    """
    try:
        # Extract nginx headers
        path = request.headers.get('X-Original-URI')
        method = request.headers.get('X-Original-Method')

        # Extract credentials
        api_key = extract_api_key(request.headers)
        hmac_sig = extract_hmac_components(request.headers)

        # Authorize
        result = authorizer.authorize_request(path, method, api_key, hmac_sig)

        if result.allowed:
            response = make_response('', 200)
            if result.client_id:
                response.headers['X-Auth-Client-ID'] = result.client_id
                response.headers['X-Auth-Client-Name'] = result.client_name
            return response
        else:
            return make_response(result.reason, 403)

    except Exception as e:
        app.logger.error(f"Authorization error: {e}")
        return make_response('Internal error', 500)

@app.route('/health')
def health():
    """Health check endpoint."""
    return {'status': 'healthy', 'database': 'connected'}
```

#### 2. Nginx Configuration Example (`nginx/auth-example.conf`)

```nginx
# Upstream auth service
upstream auth_service {
    server localhost:5000;
}

# Protected API
server {
    listen 80;
    server_name api.example.com;

    # Protected routes
    location /api/ {
        # Auth subrequest
        auth_request /auth;

        # Pass client info to backend
        auth_request_set $auth_client_id $upstream_http_x_auth_client_id;
        proxy_set_header X-Client-ID $auth_client_id;

        # Proxy to backend
        proxy_pass http://backend_service;
    }

    # Auth endpoint (internal only)
    location = /auth {
        internal;
        proxy_pass http://auth_service/auth;

        # Pass original request info
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }
}
```

#### 3. Docker Setup

**Dockerfile**:
```dockerfile
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ src/
COPY pyproject.toml .
RUN pip install -e .

CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "4", "src.app:app"]
```

**docker-compose.yml**:
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: api_auth_admin
      POSTGRES_PASSWORD: ${API_AUTH_ADMIN_PG_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  auth-service:
    build: .
    ports:
      - "5000:5000"
    environment:
      API_AUTH_ADMIN_PG_PASSWORD: ${API_AUTH_ADMIN_PG_PASSWORD}
      POSTGRES_HOST: postgres
    depends_on:
      - postgres

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/auth-example.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - auth-service

volumes:
  postgres_data:
```

### Tests to Write

**Flask Application Tests**:
- Test with Flask test client (no actual nginx)
- Mock X-Original-URI and X-Original-Method headers
- Test allow scenarios (200 response)
- Test deny scenarios (403 response)
- Test error handling (500 response)
- Verify headers set correctly

**Integration Tests** (optional):
- Full stack with nginx + auth service + mock backend
- Real HTTP requests through nginx
- Verify auth_request integration

### Success Criteria

- [ ] Flask application with /auth endpoint
- [ ] Health check endpoint
- [ ] Nginx header extraction
- [ ] Response headers for upstream (X-Auth-Client-ID)
- [ ] Error handling and logging
- [ ] Nginx configuration example
- [ ] Docker setup (Dockerfile + compose)
- [ ] Test suite with Flask test client
- [ ] Documentation for nginx integration

### Estimated Effort

**Development**: 3-4 hours
**Testing**: 2-3 hours
**Documentation**: 2 hours
**Total**: ~1 day

---

## Phase 4: Integration & Production Readiness

**Goal**: Make the system production-ready

### Tasks

#### 1. Performance Optimization

**Caching Layer**:
- Cache routes (changes infrequent)
- Cache client credentials (with TTL)
- Cache permissions (invalidate on updates)
- Consider Redis for distributed caching

**Benchmarking**:
- Measure authorization latency (target: <10ms)
- Load testing with realistic traffic
- Identify and optimize hot paths
- Database query optimization

#### 2. Monitoring & Observability

**Metrics** (Prometheus format):
- `auth_requests_total{result="allowed|denied"}`
- `auth_duration_seconds{route, method}`
- `auth_errors_total{type}`
- `db_connection_pool{state="active|idle"}`

**Structured Logging**:
```python
logger.info("Authorization result", extra={
    'client_id': result.client_id,
    'route': path,
    'method': method,
    'allowed': result.allowed,
    'reason': result.reason,
    'duration_ms': elapsed
})
```

**Health Checks**:
- Database connectivity
- Connection pool status
- Cache connectivity (if used)

#### 3. Documentation

**Guides**:
- Nginx integration guide
- Client SDK examples (Python, JavaScript, cURL)
- Deployment guide (Docker, Kubernetes)
- Troubleshooting guide

**API Documentation**:
- /auth endpoint specification
- Header requirements
- Response codes and meanings
- Example requests/responses

#### 4. CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
      - name: Install dependencies
        run: pip install -r requirements.txt -r dev-requirements.txt
      - name: Run tests
        run: pytest --cov=src
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

### Success Criteria

- [ ] Caching implemented (optional but recommended)
- [ ] Performance benchmarks documented
- [ ] Prometheus metrics exposed
- [ ] Structured logging throughout
- [ ] Health check endpoint
- [ ] Complete deployment documentation
- [ ] CI/CD pipeline configured
- [ ] Load testing results

### Estimated Effort

**Development**: 5-6 hours
**Documentation**: 3-4 hours
**Testing/Tuning**: 3-4 hours
**Total**: 2 days

---

## Phase 5: Enhancement Features (Future)

**Nice-to-haves after core is production-ready**

### Rate Limiting

**Per-client rate limits**:
- Add `rate_limit` field to clients table
- Implement sliding window or token bucket algorithm
- Return 429 Too Many Requests when exceeded

### Admin REST API

**Alternative to CLI scripts**:
```
POST   /api/routes           # Create route
GET    /api/routes           # List routes
DELETE /api/routes/:id       # Delete route
POST   /api/clients          # Create client
GET    /api/clients          # List clients
POST   /api/permissions      # Grant permission
GET    /api/permissions      # List permissions
DELETE /api/permissions/:id  # Revoke permission
```

### Audit Logging

**Track all access**:
- Who accessed what endpoint
- When (timestamp)
- Result (allowed/denied)
- Reason
- Store in separate audit table

### Credential Rotation

**Tools for rotating credentials**:
```bash
python scripts/rotate_client_credentials.py <client_id>
# Generates new credentials
# Updates database
# Returns both old and new (grace period)
```

### Web Dashboard

**Browser-based administration**:
- View routes, clients, permissions
- Grant/revoke access
- View audit logs
- Manage client lifecycle

### Client SDKs

**Official libraries**:
- Python client library
- JavaScript/Node.js client
- Go client
- Request signing helpers

### Webhooks

**Event notifications**:
- Client suspended
- Rate limit exceeded
- Authentication failures threshold
- POST to configured webhook URL

---

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: Authorization Engine | 1 day | None (ready to start) |
| Phase 2: Authentication Handlers | 1 day | Phase 1 |
| Phase 3: Flask HTTP Endpoint | 1 day | Phase 2 |
| Phase 4: Production Readiness | 2 days | Phase 3 |
| **Core Complete** | **5 days** | |
| Phase 5: Enhancements | Ongoing | Phase 4 |

**Total to production-ready**: ~1 week of focused development

---

## Next Steps

**Immediate**: Start Phase 1 - Authorization Engine

1. Create `src/auth/` directory
2. Build `AuthResult` model
3. Implement `Authorizer` class
4. Write comprehensive tests
5. Validate with existing database configuration

**After Phase 1**: Review and plan Phase 2 (Authentication Handlers)
