# Database Setup Guide

This guide explains how to set up the PostgreSQL database for the API Authentication Service.

## Prerequisites

- PostgreSQL installed and running
- Python 3.13+ with psycopg2 installed
- Access to PostgreSQL superuser account (default: `postgres`)

## Environment Variables

### Required Environment Variables

You must set these environment variables before running the setup script:

#### Global (PostgreSQL superuser credentials)
```bash
export PG_PASSWORD="your_postgres_superuser_password"
```

#### Project-specific (API Auth Service)
```bash
export API_AUTH_ADMIN_PG_PASSWORD="your_app_password"
```

### Optional Environment Variables

These have sensible defaults but can be overridden:

#### PostgreSQL Connection
- `POSTGRES_HOST` - PostgreSQL host (default: `localhost`)
- `POSTGRES_PORT` - PostgreSQL port (default: `5432`)
- `POSTGRES_USER` - PostgreSQL superuser (default: `postgres`)

#### Application Database
- `API_AUTH_ADMIN_PG_DB` - Database name (default: `api_auth_admin`)
- `API_AUTH_ADMIN_PG_USER` - Application user (default: `api_auth_admin`)

## Setup Instructions

### 1. Set Environment Variables

Create a `.env` file or export variables in your shell:

```bash
# PostgreSQL superuser password (required)
export PG_PASSWORD="your_postgres_password"

# API Auth Service password (required)
export API_AUTH_ADMIN_PG_PASSWORD="your_secure_password_here"

# Optional: Override defaults if needed
# export POSTGRES_HOST="localhost"
# export POSTGRES_PORT="5432"
# export API_AUTH_ADMIN_PG_DB="api_auth_admin"
# export API_AUTH_ADMIN_PG_USER="api_auth_admin"
```

### 2. Run the Setup Script

#### Setup Main Database

```bash
source bin/activate && python dev_scripts/setup_database.py
```

This will:
1. Create the `api_auth_admin` user (if it doesn't exist)
2. Create the `api_auth_admin` database (if it doesn't exist)
3. Grant all privileges to the user
4. Apply the schema from `src/database/schema.sql`

#### Setup Test Database

```bash
source bin/activate && python dev_scripts/setup_database.py --test-db
```

This creates a separate `api_auth_admin_test` database for testing purposes.

## Database Schema

The setup script creates the following tables:

### `routes` Table

Stores protected API routes with HTTP method-specific authentication requirements.

**Columns:**
- `route_id` (TEXT, PRIMARY KEY) - Unique identifier for the route
- `route_pattern` (TEXT) - URL pattern (exact match or wildcard with `/*`)
- `service_name` (TEXT) - Name of the backend service
- `methods` (JSONB) - HTTP method authentication configurations
- `created_at` (BIGINT) - Unix timestamp of creation
- `updated_at` (BIGINT) - Unix timestamp of last update

**Example `methods` structure:**
```json
{
  "GET": {
    "auth_required": false,
    "auth_type": null
  },
  "POST": {
    "auth_required": true,
    "auth_type": "hmac"
  },
  "DELETE": {
    "auth_required": true,
    "auth_type": "api_key"
  }
}
```

## Using the Database Driver

After setup, use the `AuthServiceDB` class to interact with the database:

```python
from src.database import AuthServiceDB
import os

# Initialize database connection
db = AuthServiceDB(
    db_host=os.environ.get('POSTGRES_HOST', 'localhost'),
    db_name=os.environ.get('API_AUTH_ADMIN_PG_DB', 'api_auth_admin'),
    db_user=os.environ.get('API_AUTH_ADMIN_PG_USER', 'api_auth_admin'),
    db_password=os.environ['API_AUTH_ADMIN_PG_PASSWORD']
)

# Load a route by ID
route = db.load_route_by_id('some-route-id')

# Find matching routes for a path
matching_routes = db.find_matching_routes('/api/users/123')

# Save a route
from src.models.route import Route, HttpMethod
from src.models.method_auth import MethodAuth, AuthType

route = Route.create_new(
    route_id='api-users',
    route_pattern='/api/users/*',
    service_name='user-service',
    methods={
        HttpMethod.GET: MethodAuth(auth_required=False),
        HttpMethod.POST: MethodAuth(auth_required=True, auth_type=AuthType.HMAC)
    }
)
db.save_route(route)

# Close connections when done
db.close()
```

## Troubleshooting

### Connection Issues

If you get connection errors:
1. Verify PostgreSQL is running: `psql -U postgres -c "SELECT version();"`
2. Check environment variables are set correctly
3. Verify PostgreSQL is accepting connections on the specified host/port

### Permission Errors

If you get permission errors:
1. Ensure `PG_PASSWORD` is correct for the PostgreSQL superuser
2. Check that the PostgreSQL user has `CREATEDB` and `CREATEROLE` privileges

### Schema Not Applied

If tables aren't created:
1. Verify `src/database/schema.sql` exists
2. Check for SQL syntax errors in the schema file
3. Review error messages from the setup script

## Next Steps

After database setup:
1. Create sample route configurations
2. Implement authentication handlers
3. Integrate with nginx `auth_request` module
4. Set up monitoring and logging
