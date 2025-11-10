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
- **Test Suite**: 151 comprehensive unit tests with test database isolation
- **Documentation**: README, ARCHITECTURE, DATABASE_SETUP guides

**Bottom line**: Configuration layer is complete. Can define routes, create clients, and grant permissions.

### ✅ Phase 1: Authorization Engine (COMPLETED)

- **AuthResult Model**: Complete decision response model with serialization
- **Authorizer Class**: Full authorization flow with route matching and permission checking
- **Route Matching**: Exact and wildcard matching with proper priority rules
- **Public Routes**: Support for routes with no authentication required
- **Client Status**: Active/suspended/revoked client verification
- **Permission Verification**: Client + route + method access control
- **Test Coverage**: 21 comprehensive authorizer tests

### ✅ Phase 2: Authentication Handlers (COMPLETED)

- **HMACHandler**: HMAC-SHA256 signature validation using byteforge-hmac library
- **DatabaseSecretProvider**: Database integration for HMAC secret lookup
- **APIKeyHandler**: API key extraction from headers (Bearer/ApiKey/raw) and query parameters
- **RequestSigner**: Test utility for generating valid HMAC signatures
- **Updated Authorizer**: Clean interface with headers, body, query_params (no deprecated parameters)
- **Authentication Priority**: HMAC first (more secure), then API key fallback
- **Test Coverage**: 40 comprehensive authentication handler tests

**Bottom line**: Core authorization and authentication logic complete. Ready for HTTP integration.

### ✅ Phase 3: Flask HTTP Endpoint (COMPLETED)

- **Flask Application**: Production-ready auth service on port 7843 with application factory pattern
- **/authz Endpoint**: Nginx auth_request integration with full header handling
- **/health Endpoint**: Health check with database connectivity verification
- **Nginx Configuration**: Complete example with auth_request, header forwarding, client info passthrough
- **Request Body Handling**: HMAC validation with body content for POST/PUT/PATCH requests
- **Client Info Headers**: X-Auth-Client-ID, X-Auth-Client-Name, X-Auth-Route-ID passthrough
- **Query Parameter Support**: API key extraction from query strings
- **Test Data Utility**: setup_test_data.py script for manual testing scenarios
- **Test Coverage**: 16 comprehensive Flask endpoint tests (151 total tests across entire project)

**Bottom line**: Flask HTTP endpoint operational and tested. Ready for nginx integration and production deployment.

---

## Phase 1: Authorization Engine (Core Logic) ✅ **COMPLETED**

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

- [x] AuthResult model created
- [x] Authorizer class implemented
- [x] Route matching logic working (exact and wildcard)
- [x] Public route handling (no auth required)
- [x] API key authentication (basic validation)
- [x] Client status checking (active/suspended/revoked)
- [x] Permission verification (client + route + method)
- [x] Comprehensive test suite (30+ tests, all passing)
- [x] Integration with existing database models

### Estimated Effort

**Development**: 4-6 hours
**Testing**: 3-4 hours
**Total**: ~1 day

---

## Phase 2: Authentication Handlers (Crypto & Validation) ✅ **COMPLETED**

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

- [x] API key extraction from headers and query params
- [x] HMAC signature computation (HMAC-SHA256)
- [x] Timestamp validation with configurable tolerance
- [x] Body hash validation
- [x] Constant-time signature comparison
- [x] Request signing utility for tests
- [x] Integration with authorizer
- [x] Test suite for all authentication paths

### Estimated Effort

**Development**: 4-5 hours
**Testing**: 3-4 hours
**Total**: ~1 day

---

## Phase 3: Flask HTTP Endpoint (Nginx Integration) ✅ **COMPLETED**

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

- [x] Flask application with /authz endpoint
- [x] Health check endpoint
- [x] Nginx header extraction (X-Original-URI, X-Original-Method)
- [x] Response headers for upstream (X-Auth-Client-ID, X-Auth-Client-Name, X-Auth-Route-ID)
- [x] Error handling and logging
- [x] Nginx configuration example (nginx/auth-example.conf)
- [ ] Docker setup (Dockerfile + compose) - Deferred to Phase 4
- [x] Test suite with Flask test client (16 tests)
- [x] Documentation for nginx integration
- [x] Test data setup utility (scripts/setup_test_data.py)
- [x] Manual testing with curl commands
- [x] Query parameter API key support

### Estimated Effort

**Development**: 3-4 hours ✅
**Testing**: 2-3 hours ✅
**Documentation**: 2 hours ✅
**Total**: ~1 day ✅ **COMPLETED**

---

## Phase 4: Integration & Production Readiness 🎯 **CURRENT PHASE**

**Goal**: Deploy to production and establish monitoring

### Completed Tasks

#### ✅ 1. Docker Deployment Setup
- Dockerfile with Gunicorn, 4 workers, port 7843
- Automated build-publish.sh with version management
- docker-compose.example.yml for integration
- .dockerignore for optimized builds

#### ✅ 2. Monitoring & Observability
- **Prometheus metrics**: auth_requests_total, auth_duration_seconds, auth_errors_total, db_connection_pool
- **Structured JSON logging**: All requests logged with context (client_id, route, method, duration_ms)
- **Enhanced health checks**: Database connectivity, route/client counts
- **/metrics endpoint**: Prometheus exposition format
- **156 comprehensive tests**: Including endpoint tests for /health and /metrics

### Next Priority Tasks

#### ✅ 3. Docker Deployment to Production Server (COMPLETED)

**Deployed to**: http://brutus.mazza.vc:7843
- ✅ Built and deployed Docker image
- ✅ Configured environment variables via .env file
- ✅ Container running with Gunicorn (4 workers)
- ✅ Database connectivity verified
- ✅ Port 7843 accessible (now secured)
- ✅ Production test data configured (3 routes, 2 clients)

#### ✅ 4. Production Testing (COMPLETED)

**Health & Metrics Verification**:
- ✅ Tested `/health` endpoint on production - 200 OK
- ✅ Verified database connectivity - connected
- ✅ Confirmed routes_configured: 3, clients_configured: 2

**Authorization Testing**:
- ✅ Tested `/authz` endpoint with all authentication methods
- ✅ Public route handling - GET /api/test/public (200 OK)
- ✅ API key authentication (Bearer token) - /api/test/protected (200 OK)
- ✅ API key authentication (query param) - /api/test/protected?api_key=... (200 OK)
- ✅ Unauthorized access rejection - 403 FORBIDDEN with "invalid_credentials"
- ✅ Verified client headers (X-Auth-Client-ID, X-Auth-Client-Name, X-Auth-Route-ID)

**Infrastructure**:
- ✅ Created dev_scripts/setup_production_test_data.py for test data deployment
- ✅ Created .env.example with comprehensive environment variable documentation
- ✅ Enhanced python-dotenv integration throughout application

#### 5. Prometheus Dashboard Design

**Grafana Dashboard Components**:

**Overview Panel**:
- Total requests (allowed vs denied) - Pie chart
- Request rate over time - Time series
- Success rate percentage - Gauge

**Performance Metrics**:
- Authorization latency (p50, p95, p99) - Graph
- Request duration histogram - Heatmap
- Requests per second by route - Bar chart

**Error Tracking**:
- Error rate over time - Time series
- Error types breakdown - Table
- Failed authentication attempts - Counter

**Route Analysis**:
- Top routes by traffic - Bar chart
- Route-specific latency - Multi-line graph
- Allowed vs denied by route - Stacked area

**Client Monitoring**:
- Active clients - Stat panel
- Requests per client - Table
- Client authentication failures - Alert panel

**System Health**:
- Database connection status - Stat panel
- Routes configured - Stat panel
- Uptime - Stat panel

**Alerts to Configure**:
- High error rate (>5% over 5 minutes)
- Authorization latency >100ms (p95)
- Database connectivity issues
- Unusual spike in denied requests

### Lower Priority (Optional)

#### Performance Optimization

**Caching Layer** (implement if latency is an issue):
- Cache routes (changes infrequent)
- Cache client credentials (with TTL)
- Cache permissions (invalidate on updates)
- Consider Redis for distributed caching

**Benchmarking**:
- Measure authorization latency baseline
- Load testing with realistic traffic patterns
- Identify and optimize hot paths
- Database query optimization

#### Documentation

**Guides** (as needed):
- Nginx integration guide with examples
- Client SDK examples (Python, JavaScript, cURL)
- Deployment guide (Docker, Kubernetes)
- Troubleshooting guide

**API Documentation**:
- /authz endpoint specification
- Header requirements
- Response codes and meanings
- Example requests/responses

### Success Criteria

- [x] Docker deployment setup complete
- [x] Prometheus metrics exposed
- [x] Structured logging throughout
- [x] Health check endpoint implemented
- [x] Deployed to production server (brutus.mazza.vc:7843)
- [x] Production testing completed
- [ ] Prometheus dashboard created
- [ ] Monitoring alerts configured
- [ ] Performance baseline documented

### Estimated Effort

**Production Deployment**: ✅ 2-3 hours (COMPLETED)
**Production Testing**: ✅ 2-3 hours (COMPLETED)
**Prometheus Dashboard**: ✅ 2-3 hours (COMPLETED)
**Total**: ~1 day ✅ **COMPLETED**

---

## Phase 5: Domain-Based Routing 🎯 **NEXT PRIORITY**

**Goal**: Enable multi-domain support with domain-specific route configurations

**Why this phase**: Support multiple domains/services with a single gatekeeper instance, allowing different access rules per domain without running separate containers.

### Current Limitation

Routes currently match only on **path**, not domain. This means:
- `/api/users` matches on ANY domain
- Cannot have different access rules for `api.example.com/users` vs `admin.example.com/users`
- Would require multiple gatekeeper instances for multi-domain scenarios

### Requirements

**Domain Matching Support**:
- Add domain field to route configuration
- Match requests based on domain + path combination
- Support wildcard domains (`*` for "any domain", `*.example.com` for subdomains)
- Backward compatible (existing routes with no domain should work)

**Use Cases**:
- Public API (`api.example.com`) vs Admin API (`admin.example.com`) with different auth rules
- Multi-tenant applications with domain-per-tenant
- Development/staging/production environments on different subdomains

### Components to Build

#### 1. Database Schema Migration

**Add domain column to routes table**:
```sql
ALTER TABLE routes ADD COLUMN domain TEXT;
ALTER TABLE routes ADD CONSTRAINT domain_format CHECK (domain IS NULL OR domain ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$|^\*$|^\*\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$');

-- Index for efficient domain+path lookups
CREATE INDEX idx_routes_domain_pattern ON routes(domain, route_pattern);

-- Update comments
COMMENT ON COLUMN routes.domain IS 'Domain for route matching. NULL or * = any domain, *.example.com = subdomain wildcard, example.com = exact match';
```

**Migration script** (`dev_scripts/migrations/001_add_domain_to_routes.py`):
- Add domain column with default NULL (matches any domain)
- Existing routes continue to work (backward compatible)
- Add indexes for performance

#### 2. Model Updates

**Update Route model** (`src/models/route.py`):
```python
@dataclass
class Route:
    route_id: str
    route_pattern: str
    domain: Optional[str]  # NEW: NULL, *, *.example.com, example.com
    service_name: str
    methods: Dict[str, MethodAuthRequirement]
    created_at: int
    updated_at: int
```

**Validation logic**:
- Domain format validation (DNS-compatible, wildcard patterns)
- Case-insensitive domain matching
- Wildcard pattern validation

#### 3. Authorization Logic

**Update Authorizer** (`src/auth/authorizer.py`):
```python
def authorize_request(
    self,
    path: str,
    method: HttpMethod,
    domain: Optional[str] = None,  # NEW parameter
    headers: Optional[Dict[str, str]] = None,
    body: str = '',
    query_params: Optional[Dict[str, str]] = None
) -> AuthResult:
    # Match routes by domain AND path
    matching_routes = self._match_routes(path, domain)
```

**Route matching logic**:
```python
def _match_routes(self, path: str, domain: Optional[str] = None) -> List[Route]:
    """
    Find all routes that match path and domain.

    Priority:
    1. Exact domain + exact path
    2. Exact domain + wildcard path
    3. Wildcard domain + exact path
    4. Wildcard domain + wildcard path
    5. NULL domain (any domain) + exact path
    6. NULL domain (any domain) + wildcard path
    """
```

**Domain matching rules**:
- `NULL` or `*` in database → matches any domain
- Exact match: `example.com` matches only `example.com`
- Subdomain wildcard: `*.example.com` matches `api.example.com`, `admin.example.com`, etc.
- Case-insensitive comparison
- No port matching (domain only)

#### 4. HTTP Integration

**Update /authz endpoint** (`src/blueprints/authz.py`):
```python
@authz_bp.route('/authz', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def authorize():
    # Extract domain from nginx header
    original_host = request.headers.get('X-Original-Host', '')
    domain = original_host.split(':')[0] if original_host else None  # Strip port

    # Pass to authorizer
    result = authorizer.authorize_request(
        path=path,
        method=method,
        domain=domain,  # NEW
        headers=headers,
        body=body,
        query_params=query_params
    )
```

**Update nginx configuration** (`nginx/auth-example.conf`):
```nginx
location = /auth {
    internal;
    proxy_pass http://auth_service/authz;

    # Pass original request info
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-Host $host;  # NEW - pass domain
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
```

#### 5. Management Scripts

**Update create_route.py**:
```python
# Prompt for domain
domain = input("Domain (leave blank for any domain, * for wildcard): ").strip()
if not domain:
    domain = None  # Any domain
```

**Update list_routes.py**:
```python
# Display domain in table
print(f"Domain: {route.domain or '*'}")
```

**Update other scripts**:
- `delete_route.py` - Show domain in selection
- `dev_scripts/setup_test_data.py` - Add domain examples
- `dev_scripts/setup_production_test_data.py` - Add domain field

#### 6. Database Driver

**Update AuthServiceDB** (`src/database/driver.py`):
```python
def find_matching_routes(self, path: str, domain: Optional[str] = None) -> List[Route]:
    """
    Find routes matching path and domain.

    Query logic:
    - Match domain exactly, or
    - Match wildcard domain pattern, or
    - Match NULL domain (any)

    Then match path (exact or wildcard)
    Order by specificity (exact domain > wildcard > null)
    """
```

### Tests to Write

**Domain Matching Tests** (`tests/test_authorizer_domain_matching.py`):
- Exact domain match
- Wildcard subdomain match (`*.example.com`)
- Any domain match (`NULL` or `*`)
- Case-insensitive matching
- Domain priority (exact > wildcard > null)
- Path + domain combination matching
- Missing domain header (defaults to any)

**Integration Tests** (`tests/test_authz_endpoint_domain.py`):
- X-Original-Host header extraction
- Port stripping from host header
- Domain-based authorization decisions
- Multiple domains with same path

**Edge Cases**:
- Same path on different domains
- Wildcard domain conflicts
- Domain with port number
- Invalid domain formats
- IDN/Unicode domains (if needed)

### Success Criteria

- [ ] Database migration script created and tested
- [ ] Domain column added to routes table
- [ ] Route model updated with domain field
- [ ] Domain matching logic implemented in authorizer
- [ ] Domain priority rules working correctly
- [ ] X-Original-Host header extraction in /authz endpoint
- [ ] All management scripts updated
- [ ] Backward compatibility maintained (NULL domain works)
- [ ] Comprehensive test coverage (30+ tests)
- [ ] Nginx configuration example updated
- [ ] Documentation updated (README, ARCHITECTURE)
- [ ] All existing tests still passing

### Estimated Effort

**Database Migration**: 1 hour
**Model & Validation**: 1 hour
**Authorization Logic**: 2-3 hours
**HTTP Integration**: 1 hour
**Management Scripts**: 2 hours
**Testing**: 3-4 hours
**Documentation**: 1 hour
**Total**: ~1.5 days

---

## Phase 6: Enhancement Features (Future)

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

| Phase | Effort | Status | Dependencies |
|-------|--------|--------|--------------|
| Phase 1: Authorization Engine | 1 day | ✅ COMPLETED | None |
| Phase 2: Authentication Handlers | 1 day | ✅ COMPLETED | Phase 1 |
| Phase 3: Flask HTTP Endpoint | 1 day | ✅ COMPLETED | Phase 2 |
| Phase 4: Production Readiness | 1 day | ✅ COMPLETED | Phase 3 |
| Phase 5: Domain-Based Routing | 1.5 days | 🎯 NEXT | Phase 4 |
| **Core Complete** | **5.5 days** | **4 days done** | |
| Phase 6: Enhancements | Ongoing | ⏳ Pending | Phase 5 |

**Progress**: 4 of 5 core phases completed (~73% to multi-domain production-ready)

---

## Next Steps

**Immediate**: Start Phase 5 - Domain-Based Routing

1. Create database migration script
2. Update Route model with domain field
3. Implement domain matching logic in authorizer
4. Update /authz endpoint for X-Original-Host extraction
5. Update all management scripts
6. Write comprehensive tests
7. Update nginx configuration example
8. Update documentation

**After Phase 5**: Phase 6 Enhancement Features (rate limiting, admin API, audit logging, etc.)
