# API Gatekeeper Architecture

## Overview

API Gatekeeper is an authentication and authorization service designed to work with nginx's `ngx_http_auth_request_module`. It provides HMAC signature validation and API key authentication for microservices, with fine-grained permission control at the route and HTTP method level.

## Core Concepts

The system is built around three primary entities that work together to control API access:

### 1. Routes
**What they represent:** Protected API endpoints that require authentication

Routes define the API endpoints you want to protect and specify which HTTP methods require authentication. Each route:
- Has a unique pattern (exact match or wildcard like `/api/users/*`)
- Belongs to a service (e.g., `user-service`, `payment-service`)
- Defines authentication requirements per HTTP method

**Example use case:**
```
Route: /api/users/*
Service: user-service
Methods:
  - GET: No authentication required (public)
  - POST: Requires authentication (API key or HMAC)
  - DELETE: Requires authentication (API key or HMAC)
```

### 2. Clients
**What they represent:** API consumers that need access to protected routes

Clients are the entities (applications, services, or users) that make requests to your protected APIs. Each client:
- Has a unique identifier (UUID)
- Can have an API key for simple authentication
- Can have a shared secret for HMAC signature authentication
- Can have both credentials (different auth methods for different scenarios)
- Has a status (active, suspended, revoked) for access control

**Example use case:**
```
Client: Mobile App v2.1
API Key: mobile-app-key-abc123
Shared Secret: hmac-secret-xyz789
Status: active
```

### 3. Permissions
**What they represent:** The glue that connects clients to routes

Permissions define which clients can access which routes and with which HTTP methods. Each permission:
- Links a specific client to a specific route
- Specifies which HTTP methods the client can use
- Is automatically deleted if the client or route is removed (cascade delete)

**Example use case:**
```
Permission:
  Client: Mobile App v2.1
  Route: /api/users/*
  Allowed Methods: [GET, POST]

  Result: Mobile app can GET and POST to /api/users/* but cannot DELETE
```

## How They Work Together

```
┌─────────────┐
│   Client    │  "Who is making the request?"
│             │
│ - API Key   │
│ - Secret    │
│ - Status    │
└──────┬──────┘
       │
       │ linked by
       │
       ▼
┌─────────────┐
│ Permission  │  "What are they allowed to do?"
│             │
│ - Client ID │
│ - Route ID  │
│ - Methods   │
└──────┬──────┘
       │
       │ linked to
       │
       ▼
┌─────────────┐
│   Route     │  "What endpoint and how?"
│             │
│ - Pattern   │
│ - Service   │
│ - Auth Reqs │
└─────────────┘
```

## Request Flow

When a request comes in, the authorization logic follows this flow:

1. **Extract Credentials**
   - Look for API key in headers or query params
   - Or look for HMAC signature components

2. **Identify Client**
   - Load client by API key or shared secret
   - Verify client status is "active"

3. **Match Route**
   - Find route that matches the request path
   - Could be exact match or wildcard match

4. **Check Route Requirements**
   - Does this HTTP method require authentication?
   - If not required, allow the request
   - If required, continue to permission check

5. **Verify Permission**
   - Does the client have permission for this route?
   - Is the HTTP method in the allowed methods list?
   - If yes, allow the request
   - If no, deny the request

## Database Schema

### Routes Table
```sql
routes (
  route_id UUID PRIMARY KEY,
  route_pattern TEXT,           -- e.g., "/api/users/*"
  service_name TEXT,            -- e.g., "user-service"
  methods JSONB,                -- Auth requirements per HTTP method
  created_at BIGINT,            -- Unix timestamp
  updated_at BIGINT             -- Unix timestamp
)
```

### Clients Table
```sql
clients (
  client_id UUID PRIMARY KEY,
  client_name TEXT,             -- Human-readable name
  api_key TEXT UNIQUE,          -- For simple auth (nullable)
  shared_secret TEXT UNIQUE,    -- For HMAC auth (nullable)
  status TEXT,                  -- active, suspended, revoked
  created_at BIGINT,            -- Unix timestamp
  updated_at BIGINT             -- Unix timestamp
)
```

### Client Permissions Table
```sql
client_permissions (
  permission_id UUID PRIMARY KEY,
  client_id UUID REFERENCES clients(client_id) ON DELETE CASCADE,
  route_id UUID REFERENCES routes(route_id) ON DELETE CASCADE,
  allowed_methods TEXT[],       -- e.g., ['GET', 'POST']
  created_at BIGINT,            -- Unix timestamp

  UNIQUE(client_id, route_id)   -- One permission per client/route pair
)
```

## Authentication Types

### API Key Authentication
**Use case:** Simple authentication for less sensitive operations

- Client includes API key in request header or query param
- System looks up client by API key
- Validates client is active
- Checks permissions

**Pros:**
- Simple to implement
- Easy to use
- Good for public APIs with rate limiting

**Cons:**
- Key can be intercepted if not using HTTPS
- No request tampering protection
- No timestamp validation

### HMAC Signature Authentication
**Use case:** Secure authentication for sensitive operations

- Client signs request with shared secret
- System validates signature using stored shared secret
- Protects against request tampering
- Can include timestamp to prevent replay attacks

**Pros:**
- Secure even if request is intercepted
- Protects request integrity
- Can prevent replay attacks

**Cons:**
- More complex to implement
- Requires time synchronization
- Client must implement signing logic

## Design Principles

### 1. Separation of Concerns
- **Routes** define what needs protection (policy)
- **Clients** define who can authenticate (identity)
- **Permissions** define who can access what (authorization)

### 2. Flexibility
- Routes can have mixed auth requirements (public GET, authenticated POST)
- Clients can have multiple credential types
- Permissions are granular at the HTTP method level

### 3. Security
- Credentials are unique across all clients
- Client status allows quick revocation
- Cascade deletes prevent orphaned permissions
- Unix timestamps avoid timezone issues

### 4. Scalability
- Database-driven configuration (no code changes needed)
- Indexed lookups for fast credential validation
- Connection pooling for high concurrency
- Stateless design (no session storage)

## Example Scenario

**Setup:**
```
Route 1: /api/products/*
  GET: No auth required
  POST: Auth required (API key)
  DELETE: Auth required (HMAC)

Route 2: /api/admin/*
  All methods: Auth required (HMAC)

Client A: "Mobile App" (API key only)
Client B: "Admin Dashboard" (HMAC only)
Client C: "Partner Integration" (Both)

Permissions:
  Mobile App → /api/products/* [GET, POST]
  Admin Dashboard → /api/admin/* [GET, POST, DELETE]
  Partner Integration → /api/products/* [GET, POST, DELETE]
```

**Request Examples:**

1. `GET /api/products/123` (no auth)
   - ✅ Allowed - Route says GET doesn't require auth

2. `POST /api/products` with Mobile App API key
   - ✅ Allowed - Client has permission for POST on this route

3. `DELETE /api/products/123` with Mobile App API key
   - ❌ Denied - Client has no permission for DELETE (even though they have POST)

4. `DELETE /api/products/123` with Partner Integration API key
   - ❌ Denied - Route requires HMAC for DELETE, but request uses API key

5. `DELETE /api/products/123` with Partner Integration HMAC signature
   - ✅ Allowed - Client has permission and uses correct auth method

6. `POST /api/admin/users` with Admin Dashboard HMAC signature
   - ✅ Allowed - Client has permission for this route and method

## Directory Structure

```
api-gatekeeper/
├── src/
│   ├── models/              # Data models
│   │   ├── route.py         # Route model with pattern matching
│   │   ├── method_auth.py   # Auth requirements per HTTP method
│   │   ├── client.py        # Client with credentials
│   │   └── client_permission.py  # Permission linking
│   ├── database/            # Database layer
│   │   ├── schema.sql       # PostgreSQL schema
│   │   └── driver.py        # CRUD operations with connection pooling
│   └── utils/               # Utilities
│       └── db_connection.py # Database connection helper
├── scripts/                 # Management scripts
│   ├── create_route.py      # Interactive route creation
│   ├── list_routes.py       # List all routes
│   └── delete_route.py      # Delete routes by ID
├── dev_scripts/             # Development utilities
│   ├── setup_database.py    # Database initialization
│   └── verify_schema.py     # Schema verification
└── tests/                   # Test suite
    ├── conftest.py          # Test fixtures and database setup
    ├── test_database_driver.py      # Route CRUD tests
    ├── test_client_operations.py    # Client/permission CRUD tests
    └── test_route_model.py          # Model validation tests
```

## Future Components

### Not Yet Implemented

1. **Authentication Handlers**
   - HMAC signature validation logic
   - API key extraction and validation
   - Request signing utilities

2. **Authorization Engine**
   - Request validation against routes and permissions
   - Method-level access control enforcement
   - Status checking and error responses

3. **Nginx Integration**
   - HTTP endpoint for nginx auth_request module
   - Request/response format handling
   - Performance optimizations for high throughput

4. **Management API**
   - REST API for route/client/permission management
   - Bulk operations and imports
   - Audit logging

## Configuration

All configuration is database-driven:

- **Adding a new protected endpoint:** Create a route
- **Granting access to a client:** Create a permission
- **Revoking access:** Delete the permission or suspend the client
- **Changing auth requirements:** Update the route's methods configuration

No code changes or service restarts required for configuration updates.

## Monitoring and Operations

### Key Metrics to Track
- Authentication attempts (success/failure)
- Client status distribution (active/suspended/revoked)
- Route access patterns by client
- Permission deny reasons
- Database connection pool usage

### Operational Tasks
- Regular audit of client credentials
- Permission reviews for least privilege
- Route configuration validation
- Performance monitoring of route matching
- Credential rotation policies

## Security Considerations

1. **Credential Storage**
   - Consider hashing API keys and shared secrets at rest
   - Rotate credentials periodically
   - Use strong random generation for credentials

2. **Transport Security**
   - Always use HTTPS for API key authentication
   - HMAC provides additional protection but HTTPS still recommended

3. **Access Control**
   - Follow principle of least privilege for permissions
   - Regularly audit client permissions
   - Use client status to quickly revoke access

4. **Rate Limiting**
   - Implement rate limiting per client
   - Track authentication failures
   - Automatic suspension after threshold

## Performance Considerations

1. **Database Indexes**
   - All credential lookups are indexed
   - Route pattern matching uses indexes
   - Permission queries use composite indexes

2. **Connection Pooling**
   - ThreadedConnectionPool for concurrent requests
   - Configurable min/max connections
   - Automatic connection lifecycle management

3. **Caching Opportunities**
   - Cache route configurations (infrequent changes)
   - Cache client credentials (with TTL)
   - Cache permission mappings (invalidate on updates)

4. **Scaling Strategy**
   - Stateless design allows horizontal scaling
   - Database is the only shared state
   - Read replicas for read-heavy workloads
   - Consider caching layer for extreme scale
