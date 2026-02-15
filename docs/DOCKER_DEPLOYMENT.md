# Docker Deployment Guide

This guide covers deploying API Gatekeeper with Docker, from adding it to an existing stack to running a full standalone deployment with nginx.

For detailed nginx auth_request patterns, see [HOW_TO_GATEKEEPER_AUTH_NGINX.md](../HOW_TO_GATEKEEPER_AUTH_NGINX.md).

## Prerequisites

- Docker and Docker Compose
- PostgreSQL (existing or containerized)
- Redis (optional, required for rate limiting and HMAC replay protection)
- The gatekeeper image: `ghcr.io/jmazzahacks/api-gatekeeper:latest`

## Architecture Overview

```
Internet
    |
    v
  Nginx (port 80/443)
    |
    |-- auth_request --> api-gatekeeper:7843/authz
    |                        |
    |                   Checks route, client, permissions
    |                        |
    |                   PostgreSQL (routes, clients, permissions)
    |                   Redis (rate limits, nonce storage)
    |
    v (if allowed)
  Backend Service(s)
```

All services communicate over a shared Docker network using container name DNS resolution. Gatekeeper should **never** be exposed to the internet directly -- only nginx talks to it.

## Adding Gatekeeper to an Existing Docker Stack

If you already have a `docker-compose.yml` with postgres (and optionally nginx), add the gatekeeper service:

```yaml
services:
  # ... your existing services ...

  auth-service:
    image: ghcr.io/jmazzahacks/api-gatekeeper:latest
    container_name: api-gatekeeper
    environment:
      API_AUTH_ADMIN_PG_PASSWORD: ${API_AUTH_ADMIN_PG_PASSWORD}
      POSTGRES_HOST: postgres          # your postgres service name
      POSTGRES_PORT: 5432
      POSTGRES_DB: api_auth_admin
      POSTGRES_USER: postgres
      PORT: 7843
      REDIS_HOST: redis                # omit if not using rate limiting
    depends_on:
      - postgres
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7843/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    networks:
      - your-network
```

Key points:

- **Do not expose port 7843 to the host** unless you need it for debugging. In production, only nginx should reach gatekeeper over the Docker network.
- Set `POSTGRES_HOST` to the service name of your postgres container.
- Set `REDIS_HOST` to the service name of your redis container (if using rate limiting). If omitted, rate limiting is disabled.
- All services that need to communicate (nginx, gatekeeper, postgres, redis) must share the same Docker network.

### Database Initialization

The gatekeeper database and schema need to be created before the service starts. Run the schema against your dockerized postgres:

```bash
# Copy schema into the running postgres container and execute it
docker cp src/database/schema.sql your-postgres-container:/tmp/schema.sql

# Create the database and user, then apply the schema
docker exec -it your-postgres-container psql -U postgres -c \
  "CREATE DATABASE api_auth_admin;"

docker exec -it your-postgres-container psql -U postgres -c \
  "CREATE USER api_auth_admin WITH PASSWORD 'your_password';"

docker exec -it your-postgres-container psql -U postgres -c \
  "GRANT ALL PRIVILEGES ON DATABASE api_auth_admin TO api_auth_admin;"

docker exec -it your-postgres-container psql -U postgres -d api_auth_admin -f /tmp/schema.sql

# Grant schema permissions
docker exec -it your-postgres-container psql -U postgres -d api_auth_admin -c \
  "GRANT ALL ON ALL TABLES IN SCHEMA public TO api_auth_admin;
   GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO api_auth_admin;"
```

Alternatively, use the setup script from the host (with env vars pointing to the dockerized postgres):

```bash
export POSTGRES_HOST=localhost   # if postgres port is mapped to host
export POSTGRES_PORT=5432
export PG_PASSWORD=postgres_superuser_password
export API_AUTH_ADMIN_PG_PASSWORD=your_app_password

source bin/activate && python dev_scripts/setup_database.py
```

## Full Standalone Deployment

A complete `docker-compose.yml` with all services:

```yaml
services:
  nginx:
    image: nginx:latest
    container_name: nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      auth-service:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - gatekeeper-net

  auth-service:
    image: ghcr.io/jmazzahacks/api-gatekeeper:latest
    container_name: api-gatekeeper
    environment:
      API_AUTH_ADMIN_PG_PASSWORD: ${API_AUTH_ADMIN_PG_PASSWORD}
      POSTGRES_HOST: postgres
      POSTGRES_PORT: 5432
      POSTGRES_DB: api_auth_admin
      POSTGRES_USER: postgres
      PORT: 7843
      REDIS_HOST: redis
      REDIS_PORT: 6379
      DEBUG_LOCAL: "false"
      LOG_LEVEL: INFO
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7843/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    networks:
      - gatekeeper-net

  postgres:
    image: postgres:16
    container_name: postgres
    environment:
      POSTGRES_PASSWORD: ${PG_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./src/database/schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    networks:
      - gatekeeper-net

  redis:
    image: redis:7-alpine
    container_name: redis
    volumes:
      - redisdata:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    networks:
      - gatekeeper-net

volumes:
  pgdata:
  redisdata:

networks:
  gatekeeper-net:
    driver: bridge
```

Create a `.env` file alongside this compose file:

```bash
PG_PASSWORD=your_postgres_superuser_password
API_AUTH_ADMIN_PG_PASSWORD=your_app_password
```

> **Note**: The postgres `initdb.d` mount only runs on first initialization (when the data volume is empty). If you need to re-initialize, remove the `pgdata` volume first: `docker compose down -v`.

## Nginx Configuration for Docker

### Docker DNS Resolver

Add this at the top of every `server` block to use Docker's internal DNS:

```nginx
resolver 127.0.0.11 valid=10s;
```

Without this, nginx cannot resolve container names like `api-gatekeeper` or `my-backend`.

### Variable-Based Upstreams

Always use variables for upstream addresses instead of hardcoding them in `proxy_pass`:

```nginx
# Correct - re-resolves on each request
set $upstream_gatekeeper api-gatekeeper:7843;
proxy_pass http://$upstream_gatekeeper/authz;

# Wrong - resolved once at startup, breaks on container restart
proxy_pass http://api-gatekeeper:7843/authz;
```

When you hardcode the address in `proxy_pass`, nginx resolves it once at startup. If a container restarts and gets a new IP, nginx will send traffic to the old (dead) IP until nginx itself is restarted.

### The `/auth` Internal Location Block

```nginx
location = /auth {
    internal;
    set $upstream_gatekeeper api-gatekeeper:7843;
    proxy_pass http://$upstream_gatekeeper/authz;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Original-Query $query_string;
    proxy_set_header X-Original-User-Agent $http_user_agent;
}
```

See [HOW_TO_GATEKEEPER_AUTH_NGINX.md](../HOW_TO_GATEKEEPER_AUTH_NGINX.md) for the full auth_request pattern including protected locations and Cloudflare real IP restoration.

### Default Server Block to Reject Direct IP Hits

If someone hits your server by IP address instead of domain name, nginx will match the first `server` block it finds. This can cause unexpected behavior -- requests bypass your intended server blocks and may reach backends without proper auth checks.

Add a default catch-all server block that rejects anything not matching a configured domain:

```nginx
# Reject requests that don't match any configured server_name
# This prevents direct IP access from falling through to real server blocks
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;

    # Self-signed or dummy cert -- required for 443 to not error
    ssl_certificate /etc/nginx/ssl/default.crt;
    ssl_certificate_key /etc/nginx/ssl/default.key;

    # Return 444 (nginx drops the connection with no response)
    return 444;
}
```

Place this **before** your real server blocks (or in a file that loads first alphabetically, like `00-default.conf`).

To generate a self-signed cert for the default block:

```bash
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout nginx/ssl/default.key \
  -out nginx/ssl/default.crt \
  -subj "/CN=_"
```

### Cloudflare Real IP Restoration

If your server is behind Cloudflare, you must restore real client IPs. See the [Cloudflare IP restoration section](../HOW_TO_GATEKEEPER_AUTH_NGINX.md#1-restore-real-client-ips-from-cloudflare) in the nginx auth guide for the full `set_real_ip_from` block.

## Route & Client Setup

### Running Management Scripts Against a Dockerized Database

The management scripts in `scripts/` connect via environment variables. To run them against a dockerized postgres:

**Option 1: From the host** (requires postgres port mapped to host, or network access):

```bash
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432        # or your mapped port
export API_AUTH_ADMIN_PG_PASSWORD=your_app_password

source bin/activate
python scripts/list_routes.py
```

**Option 2: Via docker exec** (no port mapping needed):

```bash
# Run a script inside the gatekeeper container
docker exec -it api-gatekeeper python scripts/list_routes.py
```

### Example: Creating a Public Health Route

A route with `auth_required: false` allows unauthenticated access:

```bash
source bin/activate
python scripts/create_route.py
# Route pattern: /api/health
# Domain: * (any domain)
# Service: my-service
# Methods: GET
#   GET auth: none (public)
```

### Example: Creating a Protected API Route

```bash
# 1. Create the route
python scripts/create_route.py
# Route pattern: /api/data/*
# Domain: api.example.com
# Service: data-service
# Methods: GET, POST, DELETE
#   GET auth: api_key
#   POST auth: api_key
#   DELETE auth: hmac

# 2. Create a client
python scripts/create_client.py
# Name: My App
# Generate API key: yes
# Save the generated API key!

# 3. Grant the client permission
python scripts/grant_permission.py
# Select the client and route
# Allow: GET, POST

# 4. Verify
python scripts/show_client.py
```

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_AUTH_ADMIN_PG_PASSWORD` | Yes | -- | Password for the app database user |
| `POSTGRES_HOST` | No | `localhost` | PostgreSQL hostname |
| `POSTGRES_PORT` | No | `5432` | PostgreSQL port |
| `POSTGRES_USER` | No | `postgres` | PostgreSQL superuser (for setup) |
| `POSTGRES_DB` | No | `api_auth_admin` | Database name |
| `API_AUTH_ADMIN_PG_USER` | No | `api_auth_admin` | Application database user |
| `PORT` | No | `7843` | Flask server port |
| `REDIS_HOST` | No | -- | Redis hostname (omit to disable rate limiting) |
| `REDIS_PORT` | No | `6379` | Redis port |
| `REDIS_PASSWORD` | No | -- | Redis password |
| `REDIS_DB` | No | `0` | Redis database number |
| `LOG_LEVEL` | No | `INFO` | Log verbosity (DEBUG, INFO, WARNING, ERROR) |
| `DEBUG_LOCAL` | No | `true` | `true` for console logs, `false` for Loki |

## Common Pitfalls & Troubleshooting

### Direct IP hits bypass server blocks

**Symptom**: Requests to `http://YOUR_SERVER_IP/...` reach a backend they shouldn't.

**Cause**: Without a default server block, nginx matches the first `server` block it finds for unmatched requests.

**Fix**: Add a [default server block](#default-server-block-to-reject-direct-ip-hits) that returns 444.

### Container name resolution failures

**Symptom**: Nginx logs show `[error] ... host not found in resolver` for service names.

**Cause**: Missing `resolver 127.0.0.11 valid=10s;` in the server block.

**Fix**: Add the Docker DNS resolver directive to every server block.

### Stale DNS from hardcoded proxy_pass

**Symptom**: After a container restart, nginx returns 502 Bad Gateway.

**Cause**: Nginx resolved the container IP at startup and cached it. The restarted container has a new IP.

**Fix**: Use [variable-based upstreams](#variable-based-upstreams) (`set $upstream ...`).

### Auth failures

**Symptom**: All requests return 401 or 403.

**Debugging steps**:
1. Check gatekeeper logs: `docker logs api-gatekeeper`
2. Look for the `reason` field in log entries -- it explains why the request was denied
3. Common reasons:
   - `route_not_found` -- no route matches the requested domain + path
   - `method_not_allowed` -- the HTTP method isn't configured on the route
   - `invalid_api_key` -- the API key doesn't match any active client
   - `permission_denied` -- the client doesn't have permission for this route/method
   - `client_suspended` or `client_revoked` -- the client account is disabled

### Gatekeeper port exposed to the internet

**Symptom**: External clients can bypass nginx and hit gatekeeper directly on port 7843.

**Cause**: Port 7843 is published in `docker-compose.yml` with `ports: - "7843:7843"`.

**Fix**: Remove the `ports` mapping. Gatekeeper only needs to be reachable within the Docker network. If you need host access for debugging, bind to localhost only: `ports: - "127.0.0.1:7843:7843"`.

### Health check failing on startup

**Symptom**: Gatekeeper container keeps restarting.

**Cause**: The database isn't ready when gatekeeper starts, or the database/user hasn't been created.

**Fix**: Use `depends_on` with `condition: service_healthy` and ensure postgres has a healthcheck. Also verify the database and user exist (see [Database Initialization](#database-initialization)).

### Redis connection errors

**Symptom**: Gatekeeper exits on startup with a Redis connection error.

**Cause**: `REDIS_HOST` is set but Redis isn't reachable.

**Fix**: Either ensure Redis is running and reachable, or remove `REDIS_HOST` from the environment to disable rate limiting.
