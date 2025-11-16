# Nginx Setup Guide

This guide explains how to integrate the API Gatekeeper with nginx using the `auth_request` module.

## Quick Start

1. **Copy the example configuration:**
   ```bash
   cp nginx/example-site.conf /etc/nginx/sites-available/api.example.com
   ```

2. **Edit the configuration:**
   - Update `server_name` to your domain
   - Update `auth_service` upstream to point to your API Gatekeeper instance
   - Update `backend_api` upstream to point to your actual API service

3. **Enable the site:**
   ```bash
   ln -s /etc/nginx/sites-available/api.example.com /etc/nginx/sites-enabled/
   ```

4. **Test configuration:**
   ```bash
   nginx -t
   ```

5. **Reload nginx:**
   ```bash
   systemctl reload nginx
   ```

## How It Works

### Request Flow

```
Client Request
    ↓
Nginx receives request
    ↓
auth_request → API Gatekeeper (/authz endpoint)
    ↓
API Gatekeeper checks:
    - Domain match (X-Original-Host)
    - Route match (X-Original-URI)
    - Credentials (Authorization header)
    - Permissions
    ↓
200 OK (allowed) → Nginx forwards to backend
    ↓
Backend receives request with:
    - X-Client-ID
    - X-Client-Name
    - X-Route-ID
    - Original Authorization header

OR

403 Forbidden (denied) → Nginx returns 403 to client
```

### Key Configuration Elements

#### 1. Auth Service Upstream
```nginx
upstream auth_service {
    server brutus.mazza.vc:7843;
}
```
Points to your API Gatekeeper instance.

#### 2. Protected Location Block
```nginx
location /api/ {
    auth_request /authz;
    # ... proxy configuration
}
```
Any request to `/api/*` must pass authentication first.

#### 3. Internal Auth Endpoint
```nginx
location = /authz {
    internal;
    proxy_pass http://auth_service/authz;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-Host $host;
    # ...
}
```
Nginx calls this internally - not accessible to external clients.

#### 4. Client Info Headers
```nginx
auth_request_set $auth_client_id $upstream_http_x_auth_client_id;
proxy_set_header X-Client-ID $auth_client_id;
```
Extracts authenticated client info and passes it to your backend.

## Domain-Based Routing

The `X-Original-Host` header enables domain-based access rules:

**Example:** Different permissions for different domains

```bash
# Configure routes with specific domains
python scripts/create_route.py
# Route: /api/users
# Domain: api.example.com
# Methods: GET (public), POST (api_key)

python scripts/create_route.py
# Route: /api/users
# Domain: admin.example.com
# Methods: GET (hmac), POST (hmac), DELETE (hmac)
```

Now the same path `/api/users` has different auth requirements based on which domain the request comes from.

## Public vs Protected Routes

### Public Route (No Auth)
```nginx
location /api/public {
    # No auth_request directive
    proxy_pass http://backend_api;
}
```

Configure the route in API Gatekeeper:
```bash
python scripts/create_route.py
# Route: /api/public
# Domain: *
# Methods: GET (no auth required)
```

### Protected Route (Auth Required)
```nginx
location /api/protected {
    auth_request /authz;  # Auth required
    # ... extract client info
    proxy_pass http://backend_api;
}
```

Configure with authentication:
```bash
python scripts/create_route.py
# Route: /api/protected
# Domain: *
# Methods: GET (api_key), POST (api_key)
```

## Authentication Methods

### API Key (Simple)
Client sends:
```bash
curl https://api.example.com/api/protected \
  -H "Authorization: Bearer your-api-key-here"
```

Or via query parameter:
```bash
curl "https://api.example.com/api/protected?api_key=your-api-key-here"
```

### HMAC Signature (Secure)
Client sends:
```bash
curl https://api.example.com/api/secure \
  -H "X-Signature: computed-hmac-signature" \
  -H "X-Timestamp: 1699900000" \
  -H "X-Body-Hash: sha256-hash-of-body"
```

Use the `byteforge-hmac` library or `RequestSigner` utility to generate signatures.

## Backend Integration

Your backend API receives these headers for authenticated requests:

```
X-Client-ID: 856a850a-45f3-4f12-9cf6-64b2e8405ebf
X-Client-Name: Production Test Client
X-Route-ID: 891aea72-edda-46cc-bfd0-8254adb7607c
```

Example backend code (Python/Flask):

```python
@app.route('/api/protected')
def protected_endpoint():
    client_id = request.headers.get('X-Client-ID')
    client_name = request.headers.get('X-Client-Name')

    return {
        'message': f'Hello {client_name}',
        'client_id': client_id
    }
```

## HTTPS/SSL Configuration

For production, add SSL:

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    # ... rest of configuration
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}
```

## Troubleshooting

### Check Auth Service Health
```bash
curl http://brutus.mazza.vc:7843/health
```

### Test Auth Endpoint Directly
```bash
curl -v http://brutus.mazza.vc:7843/authz \
  -H "X-Original-URI: /api/test" \
  -H "X-Original-Method: GET" \
  -H "X-Original-Host: api.example.com" \
  -H "Authorization: Bearer your-api-key"
```

### Check Nginx Logs
```bash
tail -f /var/log/nginx/error.log
tail -f /var/log/nginx/api.example.com.access.log
```

### Common Issues

**502 Bad Gateway:**
- Auth service is down or unreachable
- Check `auth_service` upstream configuration
- Verify API Gatekeeper is running on port 7843

**403 Forbidden (always):**
- Route not configured in API Gatekeeper
- Domain mismatch (check X-Original-Host matches route domain)
- No permission granted to the client for this route
- API key invalid or client suspended

**Headers not passed to backend:**
- Check `auth_request_set` variables are defined
- Verify `proxy_set_header` directives are present
- Ensure variable names match (e.g., `$auth_client_id`)

## Performance Considerations

### Caching
Consider caching auth decisions for short periods:

```nginx
# Create a cache zone for auth responses
proxy_cache_path /var/cache/nginx/auth_cache levels=1:2 keys_zone=auth_cache:10m max_size=100m inactive=60m;

location = /authz {
    internal;
    proxy_pass http://auth_service/authz;

    # Cache successful auth responses for 60 seconds
    proxy_cache auth_cache;
    proxy_cache_key "$http_authorization$request_uri$request_method";
    proxy_cache_valid 200 60s;
    proxy_cache_valid 403 10s;

    # ... rest of configuration
}
```

**Note:** Be cautious with caching - it may cache outdated permissions. Only use if you understand the trade-offs.

### Timeouts
Adjust timeouts based on your needs:

```nginx
location = /authz {
    internal;
    proxy_pass http://auth_service/authz;

    # Auth should be fast - fail quickly if it's not
    proxy_connect_timeout 2s;
    proxy_read_timeout 2s;
    proxy_send_timeout 2s;

    # ... rest of configuration
}
```

## Multi-Domain Setup

See the second `server` block in `example-site.conf` for handling multiple domains:

- `api.example.com` - Mixed public/protected routes
- `admin.example.com` - Everything requires authentication

Each domain can have different routes and permissions configured in the API Gatekeeper.

## Next Steps

1. Set up your routes: `python scripts/create_route.py`
2. Create clients: `python scripts/create_client.py`
3. Grant permissions: `python scripts/grant_permission.py`
4. Configure nginx using the examples above
5. Test with curl or your API client
6. Monitor with Prometheus metrics at `/metrics`

For more information, see:
- [README.md](../README.md) - Project overview
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System design
- [ROADMAP.md](../ROADMAP.md) - Feature roadmap
