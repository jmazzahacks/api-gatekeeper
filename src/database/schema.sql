-- PostgreSQL Schema for API Authentication Service
-- Routes table: Stores protected API routes with method-specific auth requirements

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS routes (
    route_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_pattern TEXT NOT NULL,
    domain TEXT NOT NULL,
    service_name TEXT NOT NULL,
    methods JSONB NOT NULL,
    created_at BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
    updated_at BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,

    -- Constraints
    CONSTRAINT route_pattern_format CHECK (route_pattern ~ '^/'),
    CONSTRAINT methods_not_empty CHECK (jsonb_typeof(methods) = 'object' AND methods != '{}'::jsonb),
    CONSTRAINT domain_format CHECK (domain ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$|^\*$|^\*\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$')
);

-- Index for efficient domain+path lookups (composite index)
CREATE INDEX IF NOT EXISTS idx_routes_domain_pattern ON routes(domain, route_pattern);

-- Index for service name filtering
CREATE INDEX IF NOT EXISTS idx_routes_service ON routes(service_name);

-- Index for efficient wildcard route lookups
CREATE INDEX IF NOT EXISTS idx_routes_wildcard ON routes(route_pattern)
    WHERE route_pattern LIKE '%/*';

-- GIN index for efficient JSONB method queries
CREATE INDEX IF NOT EXISTS idx_routes_methods ON routes USING GIN(methods);

-- Comments for documentation
COMMENT ON TABLE routes IS 'Protected API routes with HTTP method-specific authentication requirements';
COMMENT ON COLUMN routes.route_id IS 'Unique identifier for the route';
COMMENT ON COLUMN routes.route_pattern IS 'URL pattern - exact match or wildcard ending with /*';
COMMENT ON COLUMN routes.domain IS 'Domain for route matching. Examples: example.com (exact), *.example.com (subdomain wildcard), * (any domain)';
COMMENT ON COLUMN routes.service_name IS 'Name of the backend service this route protects';
COMMENT ON COLUMN routes.methods IS 'JSONB object mapping HTTP methods to auth requirements: {"GET": {"auth_required": false}, "POST": {"auth_required": true, "auth_type": "hmac"}}';
COMMENT ON COLUMN routes.created_at IS 'Unix timestamp (seconds since epoch) when route was created';
COMMENT ON COLUMN routes.updated_at IS 'Unix timestamp (seconds since epoch) when route was last updated';

-- Example data structure for methods column:
-- {
--   "GET": {
--     "auth_required": false,
--     "auth_type": null
--   },
--   "POST": {
--     "auth_required": true,
--     "auth_type": "hmac"
--   },
--   "DELETE": {
--     "auth_required": true,
--     "auth_type": "api_key"
--   }
-- }

-- Clients table: Stores API clients with authentication credentials
CREATE TABLE IF NOT EXISTS clients (
    client_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_name TEXT NOT NULL,
    shared_secret TEXT,
    api_key TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
    updated_at BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,

    -- Constraints
    CONSTRAINT client_name_not_empty CHECK (length(trim(client_name)) > 0),
    CONSTRAINT client_has_credential CHECK (shared_secret IS NOT NULL OR api_key IS NOT NULL),
    CONSTRAINT client_status_valid CHECK (status IN ('active', 'suspended', 'revoked')),
    CONSTRAINT api_key_unique UNIQUE (api_key),
    CONSTRAINT shared_secret_unique UNIQUE (shared_secret)
);

-- Index for client name lookups
CREATE INDEX IF NOT EXISTS idx_clients_name ON clients(client_name);

-- Index for API key lookups (most common authentication method)
CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key)
    WHERE api_key IS NOT NULL;

-- Index for shared secret lookups (HMAC authentication)
CREATE INDEX IF NOT EXISTS idx_clients_shared_secret ON clients(shared_secret)
    WHERE shared_secret IS NOT NULL;

-- Index for filtering active clients
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status)
    WHERE status = 'active';

-- Comments for documentation
COMMENT ON TABLE clients IS 'API clients with authentication credentials (shared secrets and/or API keys)';
COMMENT ON COLUMN clients.client_id IS 'Unique identifier for the client';
COMMENT ON COLUMN clients.client_name IS 'Human-readable name for the client';
COMMENT ON COLUMN clients.shared_secret IS 'Secret key for HMAC signature authentication (optional)';
COMMENT ON COLUMN clients.api_key IS 'API key for simple authentication (optional)';
COMMENT ON COLUMN clients.status IS 'Client account status: active, suspended, or revoked';
COMMENT ON COLUMN clients.created_at IS 'Unix timestamp (seconds since epoch) when client was created';
COMMENT ON COLUMN clients.updated_at IS 'Unix timestamp (seconds since epoch) when client was last updated';

-- Client Permissions table: Maps clients to authorized routes and methods
CREATE TABLE IF NOT EXISTS client_permissions (
    permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    route_id UUID NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
    allowed_methods TEXT[] NOT NULL,
    created_at BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,

    -- Constraints
    CONSTRAINT allowed_methods_not_empty CHECK (array_length(allowed_methods, 1) > 0),
    CONSTRAINT allowed_methods_valid CHECK (
        allowed_methods <@ ARRAY['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    ),
    -- Prevent duplicate permissions for same client/route combination
    CONSTRAINT client_route_unique UNIQUE (client_id, route_id)
);

-- Index for finding permissions by client
CREATE INDEX IF NOT EXISTS idx_permissions_client ON client_permissions(client_id);

-- Index for finding permissions by route
CREATE INDEX IF NOT EXISTS idx_permissions_route ON client_permissions(route_id);

-- GIN index for efficient array queries on allowed_methods
CREATE INDEX IF NOT EXISTS idx_permissions_methods ON client_permissions USING GIN(allowed_methods);

-- Comments for documentation
COMMENT ON TABLE client_permissions IS 'Maps clients to routes they are authorized to access with specific HTTP methods';
COMMENT ON COLUMN client_permissions.permission_id IS 'Unique identifier for the permission';
COMMENT ON COLUMN client_permissions.client_id IS 'ID of the client this permission applies to';
COMMENT ON COLUMN client_permissions.route_id IS 'ID of the route this permission grants access to';
COMMENT ON COLUMN client_permissions.allowed_methods IS 'Array of HTTP methods the client can use (e.g., {GET, POST})';
COMMENT ON COLUMN client_permissions.created_at IS 'Unix timestamp (seconds since epoch) when permission was created';
