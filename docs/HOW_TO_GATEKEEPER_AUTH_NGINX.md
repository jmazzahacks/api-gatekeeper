# How to Protect a Service with API Gatekeeper via Nginx

This documents the auth pattern for protecting backend services using the `api-gatekeeper` service as an auth gateway through nginx's `auth_request` module.

## Prerequisites

- `api-gatekeeper` container running in the same Docker network (currently on port 7843)
- The gatekeeper exposes `/authz` endpoint that validates requests and returns 200 (allow) or 401/403 (deny)
- Nginx with the `ngx_http_auth_request_module` (included by default in the official nginx Docker image)

## Architecture Overview

```
Client Request
    |
    v
  Cloudflare (CDN/proxy, terminates external TLS)
    |
    v
  Nginx (HTTPS termination, restores real client IP from CF-Connecting-IP)
    |
    |-- auth_request --> api-gatekeeper:7843/authz
    |                        |
    |                   200 = allow, 401/403 = deny
    |
    v (if allowed)
  Backend Service (e.g. materia-server:5151)
```

Every incoming request triggers a subrequest to gatekeeper. The original request is held until gatekeeper responds. If gatekeeper returns 200, nginx forwards the request to the backend. If gatekeeper returns 401 or 403, nginx returns that status to the client.

## Step-by-Step Setup

### 1. Restore Real Client IPs from Cloudflare

If Cloudflare is proxying traffic to your server, nginx will see Cloudflare's IPs as `$remote_addr` by default. You MUST add Cloudflare's IP ranges and use the `CF-Connecting-IP` header to restore the real client IP. Add this inside your `server` block:

```nginx
# Cloudflare real IP restoration
# IPv4 ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
# IPv6 ranges
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;
```

This MUST be added to EVERY `server` block that receives traffic through Cloudflare. Without it:
- `$remote_addr` will be a Cloudflare proxy IP, not the real client
- Access logs will show Cloudflare IPs instead of real clients
- Any IP-based access control will not work correctly
- The `X-Real-IP` header forwarded to backends will be wrong

Cloudflare publishes their IP ranges at https://www.cloudflare.com/ips/ - check periodically for updates.

### 2. Add the Internal Auth Location

Inside your HTTPS `server` block, add this location. It must be `internal` so it's not directly accessible from outside:

```nginx
# Internal auth endpoint for gatekeeper
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

Key details:
- `internal` prevents direct external access to `/auth`
- `proxy_pass_request_body off` and `Content-Length ""` avoid sending the request body to gatekeeper (it only needs headers)
- The `X-Original-*` headers tell gatekeeper what the original request looks like so it can make auth decisions based on URI, method, host, etc.
- `Authorization` is forwarded so gatekeeper can validate API keys / bearer tokens

### 3. Protect Your Service Location with `auth_request`

In the location block that proxies to your backend service, add `auth_request /auth` and extract the client identity headers that gatekeeper returns:

```nginx
location / {
    # Enable auth - every request will trigger a subrequest to /auth
    auth_request /auth;

    # Extract client info from gatekeeper's response headers
    auth_request_set $auth_client_id $upstream_http_x_auth_client_id;
    auth_request_set $auth_client_name $upstream_http_x_auth_client_name;
    auth_request_set $auth_route_id $upstream_http_x_auth_route_id;

    # Forward to your backend service
    set $upstream_myservice my-service:PORT;
    proxy_pass http://$upstream_myservice;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Pass authenticated client info to backend
    proxy_set_header X-Client-ID $auth_client_id;
    proxy_set_header X-Client-Name $auth_client_name;
    proxy_set_header X-Route-ID $auth_route_id;
}
```

The `auth_request_set` lines capture response headers from gatekeeper and make them available as nginx variables. These are then forwarded to your backend so it knows which client was authenticated.

### 4. Use Docker DNS Resolver

Since services are referenced by container name, add this at the top of your `server` block:

```nginx
resolver 127.0.0.11 valid=10s;
```

This uses Docker's internal DNS so that if containers restart and get new IPs, nginx won't cache stale addresses.

### 5. Use Variables for Upstream Addresses

Always use `set $upstream_xxx service:port` and `proxy_pass http://$upstream_xxx` rather than hardcoding the address directly in `proxy_pass`. This works with the resolver to handle container restarts gracefully. If you hardcode, nginx resolves the address once at startup and won't pick up IP changes.

## Complete Example (Minimal)

```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    server_name myservice.example.com;
    return 301 https://$host$request_uri;
}

# HTTPS server
server {
    listen 443 ssl;
    server_name myservice.example.com;

    resolver 127.0.0.11 valid=10s;

    ssl_certificate /etc/nginx/ssl/myservice.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/myservice.example.com.key;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Cloudflare real IP restoration
    # IPv4 ranges
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    # IPv6 ranges
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;

    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;

    # Internal auth endpoint for gatekeeper
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

    # Protected service
    location / {
        auth_request /auth;

        auth_request_set $auth_client_id $upstream_http_x_auth_client_id;
        auth_request_set $auth_client_name $upstream_http_x_auth_client_name;
        auth_request_set $auth_route_id $upstream_http_x_auth_route_id;

        set $upstream_myservice my-service:8080;
        proxy_pass http://$upstream_myservice;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header X-Client-ID $auth_client_id;
        proxy_set_header X-Client-Name $auth_client_name;
        proxy_set_header X-Route-ID $auth_route_id;
    }
}
```

## Common Pitfalls

- **Missing Cloudflare real IP restoration** means `$remote_addr`, logs, and `X-Real-IP` all show Cloudflare proxy IPs instead of real clients. This must be in EVERY server block behind Cloudflare.
- **Forgetting `internal`** on the `/auth` location exposes gatekeeper directly to the internet
- **Forgetting `proxy_pass_request_body off`** sends request bodies to gatekeeper unnecessarily, which can cause issues with large POST requests
- **Hardcoding upstream addresses** instead of using `set $variable` means nginx won't handle container IP changes after restarts
- **Missing `resolver`** directive causes DNS resolution failures for container names
- **Not forwarding `Authorization`** header means gatekeeper can't validate API keys
