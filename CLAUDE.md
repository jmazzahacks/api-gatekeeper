# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an API authentication service designed to work with nginx's `ngx_http_auth_request_module`. The service provides HMAC signature validation and API key authentication for microservices.

**Key Architectural Goals:**
- Nginx-compatible auth service that approves/denies access to protected endpoints
- User database with shared secrets and API keys for endpoint-level permissions
- Endpoint-aware authorization: determine which HTTP methods (GET, POST, etc.) require authentication
- Separate from the identity provider (IdP) - this is for API access control, not user sessions

## Python Environment

This project uses a Python 3.13 virtual environment located in the repository root.

**Running Python:**
```bash
source bin/activate && python
```

**Installing packages:**
```bash
source bin/activate && pip install <package>
```

## Database Design

- All timestamps MUST be stored as Unix timestamps (integer seconds since epoch)
- Use PostgreSQL with `RealDictCursor` for all queries and model initialization
- Never use `TIMESTAMPTZ`, `TIMESTAMP`, or `datetime` columns for storage
- Python `datetime` may only be used for output formatting or timezone conversions, never as object fields
- Route IDs are auto-generated UUIDs (don't manually specify route_id when creating routes)

## Database Connection for Scripts

**IMPORTANT**: Always use the utility function for database connections in scripts:

```python
from src.utils import get_db_connection

# Connect to database (handles all env vars, validation, and error handling)
db = get_db_connection()
```

The `get_db_connection()` utility (`src/utils/db_connection.py`):
- Loads database configuration from environment variables
- Validates required variables (API_AUTH_ADMIN_PG_PASSWORD)
- Creates and returns an `AuthServiceDB` instance
- Handles connection errors with proper messaging
- Optional `verbose` parameter (default: True) for connection status output

**Never duplicate database connection logic** - always use this utility function.

## Data Models

Data models (Client, Route, ClientPermission, RateLimit, etc.) live in the external `api-gatekeeper-models` library. Import from there:

```python
from api_gatekeeper_models import Client, Route, HttpMethod, MethodAuth, AuthType
```

Do NOT create model classes in `src/models/` — that directory has been removed in favor of the shared library.

## Code Structure

The `src/` directory contains the main application code:

- **`src/auth/`**: Authentication handlers (HMAC, API key) and authorization engine
- **`src/blueprints/`**: Flask blueprints (authz, health, metrics)
- **`src/database/`**: Database driver and schema
- **`src/utils/`**: Utility functions (db connection helper)
- **`src/app.py`**: Flask application factory
- **`src/monitoring.py`**: Prometheus metrics
- **`src/rate_limiter.py`**: Redis-backed rate limiting

## Testing

When a pytest test suite exists:
- Run all tests after making changes: `source bin/activate && pytest`
- Run a single test: `source bin/activate && pytest path/to/test_file.py::test_function_name`
