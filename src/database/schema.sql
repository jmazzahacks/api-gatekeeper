-- PostgreSQL Schema for API Authentication Service
-- Routes table: Stores protected API routes with method-specific auth requirements

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS routes (
    route_id TEXT PRIMARY KEY,
    route_pattern TEXT NOT NULL,
    service_name TEXT NOT NULL,
    methods JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,

    -- Constraints
    CONSTRAINT route_pattern_format CHECK (route_pattern ~ '^/'),
    CONSTRAINT methods_not_empty CHECK (jsonb_typeof(methods) = 'object' AND methods != '{}'::jsonb)
);

-- Index for efficient route pattern lookups
CREATE INDEX IF NOT EXISTS idx_routes_pattern ON routes(route_pattern);

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
