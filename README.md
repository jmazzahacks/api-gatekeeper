# API Gatekeeper

A flexible authentication and authorization service designed to work with nginx's `ngx_http_auth_request_module`. Provides HMAC signature validation and API key authentication for microservices with fine-grained permission control.

## Features

- **Multiple Authentication Methods**: API Key (simple) or HMAC signatures (secure)
- **Route-Based Protection**: Define which endpoints require authentication
- **Method-Level Permissions**: Control access per HTTP method (GET, POST, DELETE, etc.)
- **Client Management**: Issue credentials and manage client lifecycle
- **Flexible Permissions**: Grant specific clients access to specific routes with specific methods
- **Database-Driven**: All configuration in PostgreSQL - no code changes needed
- **Complete Management Scripts**: Interactive CLI tools for all operations

## Architecture

The system is built around three core entities:

1. **Routes**: Define protected API endpoints and their auth requirements per HTTP method
2. **Clients**: API consumers with credentials (API keys and/or shared secrets)
3. **Permissions**: Connect clients to routes with allowed HTTP methods

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation.

## Quick Start

### Prerequisites

- Python 3.13+
- PostgreSQL 12+
- Virtual environment

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd api-gatekeeper

# Create and activate virtual environment
python3.13 -m venv .
source bin/activate  # On Windows: bin\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Install package in editable mode
pip install -e .

# Set up environment variables
cp example.env .env
# Edit .env with your PostgreSQL credentials
```

### Database Setup

```bash
# Set required environment variables
export PG_PASSWORD="your_postgres_superuser_password"
export API_AUTH_ADMIN_PG_PASSWORD="your_app_password"

# Create and initialize database
source bin/activate
python dev_scripts/setup_database.py

# Create test database (for running tests)
python dev_scripts/setup_database.py --test-db
```

See [DATABASE_SETUP.md](DATABASE_SETUP.md) for detailed setup instructions.

## Management Scripts

All management scripts support both interactive and command-line modes. Run without arguments for interactive mode.

### Route Management

#### Create a Route

```bash
python scripts/create_route.py
```

Interactive prompts guide you through:
- Route pattern (e.g., `/api/users/*`)
- Service name
- HTTP methods to support
- Authentication requirements per method (none, API key, or HMAC)

**Example:**
```
Route pattern: /api/users/*
Service: user-service
Methods:
  GET: Public (no auth required)
  POST: Requires api_key
  DELETE: Requires hmac
```

#### List Routes

```bash
python scripts/list_routes.py
```

Displays all configured routes with their patterns, services, and supported methods.

#### Delete a Route

```bash
# Interactive mode
python scripts/delete_route.py

# Direct mode with route ID
python scripts/delete_route.py <route_id>
```

Confirmation required. Cascade deletes associated permissions.

### Client Management

#### Create a Client

```bash
python scripts/create_client.py
```

Interactive prompts for:
- Client name
- Credential type (API key, shared secret, or both)
- Auto-generates secure credentials or accepts custom values
- Client status (active, suspended, revoked)

**Features:**
- Uses Python's `secrets` module for secure credential generation
- Credentials are displayed once - save them securely

#### List Clients

```bash
python scripts/list_clients.py
```

Shows all clients with truncated credentials (first 8 characters) for security.

**Output includes:**
- Client ID and name
- Credential types (API key and/or shared secret)
- Status (active/suspended/revoked)

#### Delete a Client

```bash
# Interactive mode
python scripts/delete_client.py

# Direct mode with client ID
python scripts/delete_client.py <client_id>
```

**Safety features:**
- Shows associated permissions before deletion
- Requires typing 'delete' to confirm
- Cascade deletes all client permissions

### Permission Management

#### Grant Permissions

```bash
# Interactive mode - select client and route visually
python scripts/grant_permission.py

# Direct mode - provide IDs
python scripts/grant_permission.py <client_id> <route_id>
```

**Interactive mode walks you through:**
1. Select a client from list (shows credentials and status)
2. Select a route from list (shows service and methods)
3. Choose which HTTP methods to allow
4. Review and confirm

**Features:**
- Detects existing permissions and offers to update
- Shows route auth requirements for each method
- Visual indicators for active/inactive clients

#### List Permissions

```bash
# All permissions grouped by client
python scripts/list_permissions.py

# Permissions for a specific client
python scripts/list_permissions.py --client <client_id>

# Permissions for a specific route (who can access it)
python scripts/list_permissions.py --route <route_id>
```

**Output includes:**
- Client information (name, credentials, status)
- Route patterns and services
- Allowed HTTP methods
- Permission IDs (for revocation)

**By route view shows:**
- Route's authentication requirements per method
- All clients with access and their allowed methods
- Client status indicators

#### Revoke Permissions

```bash
# Interactive mode - select from all permissions
python scripts/revoke_permission.py

# By permission ID
python scripts/revoke_permission.py <permission_id>

# By client and route IDs
python scripts/revoke_permission.py <client_id> <route_id>
```

**Safety features:**
- Shows full permission details before deletion
- Displays affected client and route
- Requires typing 'revoke' to confirm

## Example Workflow

Here's a typical setup workflow:

```bash
# 1. Create a route for your API
python scripts/create_route.py
# Route: /api/products/*
# Service: product-service
# GET: Public, POST: API Key, DELETE: HMAC

# 2. Create a client
python scripts/create_client.py
# Name: Mobile App v2.1
# Generate API key: yes
# Generate shared secret: yes

# 3. Grant the client permission
python scripts/grant_permission.py
# Select: Mobile App v2.1
# Select: /api/products/*
# Allow: GET, POST (but not DELETE)

# 4. Verify configuration
python scripts/list_permissions.py --client <client_id>
# Shows: Mobile App can GET and POST to /api/products/*

# 5. View who can access a route
python scripts/list_permissions.py --route <route_id>
# Shows: All clients with access to /api/products/*
```

## Testing

Run the test suite:

```bash
# Run all tests
source bin/activate
python -m pytest

# Run specific test file
python -m pytest tests/test_client_operations.py

# Run with coverage
python -m pytest --cov=src tests/

# Run with verbose output
python -m pytest -v
```

**Test database:**
- All tests use `api_auth_admin_test` database
- Automatic cleanup between tests
- 74 tests covering routes, clients, and permissions

## Project Structure

```
api-gatekeeper/
├── src/
│   ├── models/              # Data models
│   │   ├── route.py         # Route with pattern matching
│   │   ├── method_auth.py   # Auth requirements per HTTP method
│   │   ├── client.py        # Client with credentials
│   │   └── client_permission.py  # Permission linking
│   ├── database/            # Database layer
│   │   ├── schema.sql       # PostgreSQL schema
│   │   └── driver.py        # CRUD operations with connection pooling
│   └── utils/               # Utilities
│       └── db_connection.py # Database connection helper
├── scripts/                 # Management scripts
│   ├── create_route.py      # Create routes
│   ├── list_routes.py       # List all routes
│   ├── delete_route.py      # Delete routes
│   ├── create_client.py     # Create clients
│   ├── list_clients.py      # List all clients
│   ├── delete_client.py     # Delete clients
│   ├── grant_permission.py  # Grant permissions
│   ├── list_permissions.py  # List permissions
│   └── revoke_permission.py # Revoke permissions
├── tests/                   # Test suite
│   ├── conftest.py          # Test fixtures
│   ├── test_database_driver.py      # Route CRUD tests
│   ├── test_client_operations.py    # Client/permission tests
│   └── test_route_model.py          # Model validation tests
└── dev_scripts/             # Development utilities
    └── setup_database.py    # Database initialization
```

## Configuration

All configuration is database-driven:

- **Add a protected endpoint**: Create a route
- **Grant access to a client**: Create a permission
- **Revoke access**: Delete the permission or suspend the client
- **Change auth requirements**: Update the route

No code changes or service restarts required.

## Environment Variables

### Required

- `API_AUTH_ADMIN_PG_PASSWORD`: Password for application database user

### Optional (with defaults)

- `POSTGRES_HOST`: PostgreSQL host (default: `localhost`)
- `POSTGRES_PORT`: PostgreSQL port (default: `5432`)
- `POSTGRES_USER`: PostgreSQL superuser (default: `postgres`)
- `PG_PASSWORD`: Superuser password (only needed for setup)
- `API_AUTH_ADMIN_PG_DB`: Database name (default: `api_auth_admin`)
- `API_AUTH_ADMIN_PG_USER`: Application user (default: `api_auth_admin`)

## Security Considerations

### Credentials

- API keys and shared secrets are unique across all clients
- Use auto-generation for cryptographically secure credentials
- Credentials are displayed only at creation time
- Consider implementing periodic credential rotation

### Client Status

- Use `suspended` status for temporary access revocation
- Use `revoked` status for permanent termination
- Active clients can be filtered efficiently via database indexes

### Transport Security

- Always use HTTPS for API key authentication
- HMAC provides request integrity but HTTPS is still recommended
- Implement rate limiting per client
- Monitor authentication failures

### Database

- Connection pooling prevents resource exhaustion
- All credentials are indexed for fast lookup
- Cascade deletes prevent orphaned permissions
- Unix timestamps avoid timezone-related bugs

## Development

### Adding New Features

1. Models go in `src/models/`
2. Database operations in `src/database/driver.py`
3. Update `src/database/schema.sql` for schema changes
4. Add tests in `tests/`
5. Run full test suite before committing

### Database Migrations

Currently using `schema.sql` with `CREATE TABLE IF NOT EXISTS`. For production, implement proper migrations.

### Code Style

- Follow PEP 8 conventions
- Use type hints for parameters and return types
- Methods should be under 50 lines when possible
- No sys.path hacks - use proper package installation
- Unix timestamps for all date/time storage

## Roadmap

### Implemented ✓

- [x] Route configuration with method-level auth requirements
- [x] Client management with multiple credential types
- [x] Permission system linking clients to routes
- [x] Complete management scripts (CLI)
- [x] Comprehensive test suite (74 tests)
- [x] Database schema with proper constraints
- [x] Connection pooling and CRUD operations

### In Progress

- [ ] Authorization engine (request validation logic)
- [ ] Authentication handlers (API key and HMAC validation)
- [ ] Flask HTTP endpoint for nginx integration
- [ ] Request signing utilities for testing

### Planned

- [ ] Rate limiting per client
- [ ] Audit logging
- [ ] Credential rotation policies
- [ ] Admin REST API
- [ ] Monitoring and metrics
- [ ] Caching layer for performance

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design principles
- [DATABASE_SETUP.md](DATABASE_SETUP.md) - Detailed database setup instructions
- [PROJECT_GOALS.txt](PROJECT_GOALS.txt) - Original project goals and motivation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass: `python -m pytest`
5. Submit a pull request

## License

[Your License Here]

## Support

For issues and questions:
- GitHub Issues: [repository-url]/issues
- Documentation: See ARCHITECTURE.md for detailed system design

---

**Status**: Core functionality complete. Authorization engine and HTTP endpoint in development.
